using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Services;

// One observed packet, reduced to what behavioural detection needs.
public readonly record struct PacketObservation(
    string SourceIp,
    string DestinationIp,
    int DestinationPort,
    byte Protocol,
    bool IsSyn,
    bool IsRst,
    int PacketSize,
    DateTime Timestamp);

// Detects aggregate behaviour across many short flows from one source (port scans,
// brute-force runs, floods) that a single flow cannot reveal. Also tracks a global
// packet rate so a spoofed/random-source flood is still caught.
public sealed class SourceBehaviorTracker
{
    private readonly TimeSpan _window;
    private readonly int _portScanDistinctPorts;
    private readonly int _bruteForceConnections;
    private readonly int _icmpFloodPackets;
    private readonly int _floodPackets;
    private readonly int _floodDistinctPorts;
    private readonly int _globalFloodPackets;
    private readonly TimeSpan _cooldown;

    private readonly object _lock = new();
    private readonly Dictionary<string, SourceWindow> _sources = new();

    private readonly Queue<DateTime> _globalPackets = new();
    private DateTime _globalLastFlaggedAt = DateTime.MinValue;

    private const int MaxTrackedSources = 50000;

    public SourceBehaviorTracker(
        TimeSpan window,
        int portScanDistinctPorts = 8,
        int bruteForceConnections = 5,
        TimeSpan? cooldown = null,
        int icmpFloodPackets = 50,
        int floodPackets = 200,
        int floodDistinctPorts = 20,
        int globalFloodPackets = 1000)
    {
        _window = window;
        _portScanDistinctPorts = portScanDistinctPorts;
        _bruteForceConnections = bruteForceConnections;
        _cooldown = cooldown ?? TimeSpan.FromSeconds(30);
        _icmpFloodPackets = icmpFloodPackets;
        _floodPackets = floodPackets;
        _floodDistinctPorts = floodDistinctPorts;
        _globalFloodPackets = globalFloodPackets;
    }

    public void Observe(PacketObservation packet)
    {
        lock (_lock)
        {
            _globalPackets.Enqueue(packet.Timestamp);
            TrimGlobal(packet.Timestamp);

            if (!_sources.TryGetValue(packet.SourceIp, out var window))
            {
                if (_sources.Count >= MaxTrackedSources)
                {
                    return;
                }

                window = new SourceWindow();
                _sources[packet.SourceIp] = window;
            }

            window.Add(packet, _window);
        }
    }

    // Per-packet check that returns a verdict the moment a threshold is crossed.
    public PreFilterResult? EvaluateFast(PacketObservation packet)
    {
        lock (_lock)
        {
            if (_globalPackets.Count >= _globalFloodPackets &&
                packet.Timestamp - _globalLastFlaggedAt >= _cooldown)
            {
                _globalLastFlaggedAt = packet.Timestamp;
                return PreFilterResult.SpoofedFlood(
                    AttackTypes.DoS,
                    $"Global flood: {_globalPackets.Count} packets in {_window.TotalSeconds:0}s across many sources");
            }

            if (!_sources.TryGetValue(packet.SourceIp, out var window))
            {
                return null;
            }

            window.Prune(_window);
            var verdict = Classify(window);
            if (verdict is null || packet.Timestamp - window.LastFlaggedAt < _cooldown)
            {
                return null;
            }

            window.LastFlaggedAt = packet.Timestamp;
            return verdict;
        }
    }

    private void TrimGlobal(DateTime now)
    {
        DateTime cutoff = now - _window;
        while (_globalPackets.Count > 0 && _globalPackets.Peek() < cutoff)
        {
            _globalPackets.Dequeue();
        }
    }

    // Evaluates a source's window on flow expiry. Cooldown-suppressed like EvaluateFast.
    public PreFilterResult? Evaluate(string sourceIp, DateTime now)
    {
        lock (_lock)
        {
            if (!_sources.TryGetValue(sourceIp, out var window))
            {
                return null;
            }

            window.Prune(_window);
            var verdict = Classify(window);
            if (verdict is null || now - window.LastFlaggedAt < _cooldown)
            {
                return null;
            }

            window.LastFlaggedAt = now;
            return verdict;
        }
    }

    public void Prune(DateTime now)
    {
        lock (_lock)
        {
            TrimGlobal(now);

            var stale = _sources
                .Where(kv => now - kv.Value.LastSeen > _window)
                .Select(kv => kv.Key)
                .ToList();

            foreach (var ip in stale)
            {
                _sources.Remove(ip);
            }
        }
    }

    private PreFilterResult? Classify(SourceWindow window)
    {
        var stats = window.Snapshot(_window);

        // Volume rules first: a high packet count is stronger evidence than port spread,
        // and a multi-port flood would otherwise be mislabelled as a port scan.
        if (window.TotalPackets >= _floodPackets && window.DistinctPorts.Count >= _floodDistinctPorts)
        {
            return PreFilterResult.KnownAttack(AttackTypes.DoS,
                $"Multi-port flood: {window.TotalPackets} packets across {window.DistinctPorts.Count} ports from one source",
                stats);
        }

        if (window.IcmpCount >= _icmpFloodPackets)
        {
            return PreFilterResult.KnownAttack(AttackTypes.DoS,
                $"ICMP flood: {window.IcmpCount} ICMP packets from one source", stats);
        }

        if (window.TotalPackets >= _floodPackets)
        {
            return PreFilterResult.KnownAttack(AttackTypes.DoS,
                $"Packet flood: {window.TotalPackets} packets from one source", stats);
        }

        // Port scan: many distinct destination ports probed from one source. Counts any
        // traffic to distinct ports, so SYN/connect/FIN/UDP nmap scans all trip it even
        // when replies are reset or suppressed.
        if (window.DistinctPorts.Count >= _portScanDistinctPorts)
        {
            return PreFilterResult.KnownAttack(AttackTypes.PortScan,
                $"Port scan: {window.DistinctPorts.Count} distinct ports from one source", stats);
        }

        if (window.AuthConnections >= _bruteForceConnections)
        {
            string service = window.LastAuthPort == 22 ? "SSH" : "FTP";
            return PreFilterResult.KnownAttack(AttackTypes.BruteForce,
                $"{service} brute force: {window.AuthConnections} connections from one source", stats);
        }

        if (window.SynCount >= 100 && window.AckCount == 0)
        {
            return PreFilterResult.KnownAttack(AttackTypes.DoS,
                $"TCP SYN flood: {window.SynCount} SYNs from one source", stats);
        }

        return null;
    }

    private sealed class SourceWindow
    {
        private readonly List<(DateTime Timestamp, string DestinationIp, int Port, bool IsSyn, bool IsRst, byte Protocol)> _observations = new();

        public HashSet<int> DistinctPorts { get; } = new();
        public HashSet<string> DistinctDestinationIps { get; } = new();
        public int AuthConnections { get; private set; }
        public int LastAuthPort { get; private set; }
        public int SynCount { get; private set; }
        public int AckCount { get; private set; }
        public int IcmpCount { get; private set; }
        public int TotalPackets { get; private set; }
        public DateTime LastSeen { get; private set; }

        public DateTime LastFlaggedAt { get; set; } = DateTime.MinValue;

        public void Add(PacketObservation packet, TimeSpan window)
        {
            LastSeen = packet.Timestamp;
            _observations.Add((packet.Timestamp, packet.DestinationIp, packet.DestinationPort, packet.IsSyn, packet.IsRst, packet.Protocol));
            Prune(window);
        }

        public void Prune(TimeSpan window)
        {
            if (_observations.Count == 0)
            {
                return;
            }

            DateTime cutoff = LastSeen - window;
            int firstKept = 0;
            while (firstKept < _observations.Count && _observations[firstKept].Timestamp < cutoff)
            {
                firstKept++;
            }

            if (firstKept > 0)
            {
                _observations.RemoveRange(0, firstKept);
            }

            Recompute();
        }

        public BehaviorWindowStats Snapshot(TimeSpan window) => new(
            TotalPackets,
            DistinctPorts.Count,
            DistinctDestinationIps.Count,
            SynCount,
            AckCount,
            IcmpCount,
            AuthConnections,
            window.TotalSeconds,
            DistinctPorts.OrderBy(p => p).ToList());

        private void Recompute()
        {
            DistinctPorts.Clear();
            DistinctDestinationIps.Clear();
            AuthConnections = 0;
            SynCount = 0;
            AckCount = 0;
            IcmpCount = 0;
            TotalPackets = _observations.Count;

            foreach (var (_, destinationIp, port, isSyn, _, protocol) in _observations)
            {
                DistinctPorts.Add(port);
                DistinctDestinationIps.Add(destinationIp);

                if (protocol == ProtocolNumbers.Icmp)
                {
                    IcmpCount++;
                    continue;
                }

                if (isSyn)
                {
                    SynCount++;

                    if (port == 22 || port == 21)
                    {
                        AuthConnections++;
                        LastAuthPort = port;
                    }
                }
                else
                {
                    AckCount++;
                }
            }
        }
    }
}

using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Services;

public readonly record struct PacketObservation(
    string SourceIp,
    string DestinationIp,
    int DestinationPort,
    byte Protocol,
    bool IsSyn,
    bool IsRst,
    int PacketSize,
    DateTime Timestamp,
    bool IsInbound = true,
    bool IsFin = false,
    bool IsAck = false);

public sealed class SourceBehaviorTracker
{
    private readonly TimeSpan _window;
    private readonly int _portScanDistinctPorts;
    private readonly int _portScanMaxPacketsPerPort;
    private readonly int _bruteForceConnections;
    private readonly int _bruteForceMaxPacketsPerAttempt;
    private readonly int _icmpFloodPackets;
    private readonly int _floodPackets;
    private readonly int _floodDistinctPorts;
    private readonly int _globalFloodPackets;
    private readonly int _globalFloodDistinctSources;
    private readonly int _hostSweepDistinctIps;
    private readonly int _synFloodSyns;
    private readonly TimeSpan _cooldown;
    private readonly TimeSpan _scanWindow;

    private readonly object _lock = new();
    private readonly Dictionary<string, SourceWindow> _sources = new();

    private readonly Dictionary<string, ScanWindow> _scans = new();

    private readonly Queue<(DateTime Timestamp, string SourceIp)> _globalPackets = new();
    private readonly Dictionary<string, int> _globalSourceCounts = new();
    private DateTime _globalLastFlaggedAt = DateTime.MinValue;

    private const int MaxTrackedSources = 50000;
    private const int MaxScanEntries = 4096;
    private const int MaxPacketsPerProbedHost = 2;

    private const int MaxServicePort = 49151;
    private static readonly TimeSpan ScanPruneInterval = TimeSpan.FromSeconds(1);

    public SourceBehaviorTracker(
        TimeSpan window,
        DetectionThresholds thresholds,
        TimeSpan? cooldown = null,
        TimeSpan? scanWindow = null)
    {
        _window = window;
        _portScanDistinctPorts = thresholds.PortScanDistinctPorts;
        _portScanMaxPacketsPerPort = thresholds.PortScanMaxPacketsPerPort;
        _bruteForceConnections = thresholds.BruteForceConnections;
        _bruteForceMaxPacketsPerAttempt = thresholds.BruteForceMaxPacketsPerAttempt;
        _icmpFloodPackets = thresholds.IcmpFloodSourcePackets;
        _floodPackets = thresholds.FloodPackets;
        _floodDistinctPorts = thresholds.FloodDistinctPorts;
        _globalFloodPackets = thresholds.GlobalFloodPackets;
        _globalFloodDistinctSources = thresholds.GlobalFloodDistinctSources;
        _hostSweepDistinctIps = thresholds.HostSweepDistinctIps;
        _synFloodSyns = thresholds.SynFloodSourceSyns;
        _cooldown = cooldown ?? TimeSpan.FromSeconds(30);
        _scanWindow = scanWindow ?? TimeSpan.FromMinutes(3);
    }

    public void Observe(PacketObservation packet)
    {
        if (!packet.IsInbound)
        {
            return;
        }

        lock (_lock)
        {
            _globalPackets.Enqueue((packet.Timestamp, packet.SourceIp));
            _globalSourceCounts[packet.SourceIp] = _globalSourceCounts.GetValueOrDefault(packet.SourceIp) + 1;
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
            ObserveProbe(packet);
        }
    }

    private void ObserveProbe(PacketObservation packet)
    {
        bool isTcpProbe = packet.Protocol == ProtocolNumbers.Tcp &&
            ((packet.IsSyn && !packet.IsAck) || packet.IsFin);
        bool isUdpProbe = packet.Protocol == ProtocolNumbers.Udp &&
            packet.DestinationPort <= MaxServicePort;
        bool isIcmpProbe = packet.Protocol == ProtocolNumbers.Icmp;

        if (!isTcpProbe && !isUdpProbe && !isIcmpProbe)
        {
            return;
        }

        if (!_scans.TryGetValue(packet.SourceIp, out var scan))
        {
            if (_scans.Count >= MaxTrackedSources)
            {
                return;
            }

            scan = new ScanWindow();
            _scans[packet.SourceIp] = scan;
        }

        scan.LastSeen = packet.Timestamp;
        PruneScan(scan, packet.Timestamp);
        Bump(scan.Ports, packet.DestinationPort, packet.Timestamp);
        Bump(scan.Hosts, packet.DestinationIp, packet.Timestamp);
    }

    private static void Bump<TKey>(Dictionary<TKey, ScanEntry> map, TKey key, DateTime now) where TKey : notnull
    {
        if (map.TryGetValue(key, out var entry))
        {
            map[key] = entry with { Packets = entry.Packets + 1, LastSeen = now };
        }
        else if (map.Count < MaxScanEntries)
        {
            map.Add(key, new ScanEntry(1, now));
        }
    }

    private void PruneScan(ScanWindow scan, DateTime now)
    {
        if (now - scan.LastPrunedAt < ScanPruneInterval)
        {
            return;
        }

        scan.LastPrunedAt = now;
        DropStale(scan.Ports, now);
        DropStale(scan.Hosts, now);
    }

    private void DropStale<TKey>(Dictionary<TKey, ScanEntry> map, DateTime now) where TKey : notnull
    {
        if (map.Count == 0)
        {
            return;
        }

        var stale = map.Where(kv => now - kv.Value.LastSeen > _scanWindow).Select(kv => kv.Key).ToList();
        foreach (var key in stale)
        {
            map.Remove(key);
        }
    }

    public PreFilterResult? EvaluateFast(PacketObservation packet)
    {
        lock (_lock)
        {
            if (_globalPackets.Count >= _globalFloodPackets &&
                _globalSourceCounts.Count >= _globalFloodDistinctSources &&
                packet.Timestamp - _globalLastFlaggedAt >= _cooldown)
            {
                _globalLastFlaggedAt = packet.Timestamp;
                return PreFilterResult.SpoofedFlood(
                    AttackTypes.DoS,
                    $"Distributed flood: {_globalPackets.Count} packets from {_globalSourceCounts.Count} sources in {_window.TotalSeconds:0}s");
            }

            if (!_sources.TryGetValue(packet.SourceIp, out var window))
            {
                return null;
            }

            window.Prune(_window);
            if (packet.Timestamp - window.LastFlaggedAt < _cooldown)
            {
                return null;
            }

            var verdict = Classify(window, _scans.GetValueOrDefault(packet.SourceIp));
            if (verdict is null)
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
        while (_globalPackets.Count > 0 && _globalPackets.Peek().Timestamp < cutoff)
        {
            var (_, sourceIp) = _globalPackets.Dequeue();
            if (_globalSourceCounts.TryGetValue(sourceIp, out int count))
            {
                if (count <= 1)
                {
                    _globalSourceCounts.Remove(sourceIp);
                }
                else
                {
                    _globalSourceCounts[sourceIp] = count - 1;
                }
            }
        }
    }

    public PreFilterResult? Evaluate(string sourceIp, DateTime now)
    {
        lock (_lock)
        {
            if (!_sources.TryGetValue(sourceIp, out var window))
            {
                return null;
            }

            window.Prune(_window);
            if (now - window.LastFlaggedAt < _cooldown)
            {
                return null;
            }

            var verdict = Classify(window, _scans.GetValueOrDefault(sourceIp));
            if (verdict is null)
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

            var staleScans = _scans
                .Where(kv => now - kv.Value.LastSeen > _scanWindow)
                .Select(kv => kv.Key)
                .ToList();

            foreach (var ip in staleScans)
            {
                _scans.Remove(ip);
            }
        }
    }

    private PreFilterResult? Classify(SourceWindow window, ScanWindow? scan)
    {
        BehaviorWindowStats Build() => window.Snapshot(_window);

        int probedPorts = scan is null ? 0 : scan.Ports.Count(kv => kv.Value.Packets <= _portScanMaxPacketsPerPort);
        if (probedPorts >= _portScanDistinctPorts)
        {
            return PreFilterResult.KnownAttack(AttackTypes.PortScan,
                $"Port scan: {probedPorts} ports probed from one source", Build());
        }

        int probedHosts = scan is null ? 0 : scan.Hosts.Count(kv => kv.Value.Packets <= MaxPacketsPerProbedHost);
        if (probedHosts >= _hostSweepDistinctIps)
        {
            return PreFilterResult.KnownAttack(AttackTypes.PortScan,
                $"Host sweep: {probedHosts} hosts probed from one source", Build());
        }

        if (window.TotalPackets >= _floodPackets && window.DistinctPorts.Count >= _floodDistinctPorts)
        {
            return PreFilterResult.KnownAttack(AttackTypes.DoS,
                $"Multi-port flood: {window.TotalPackets} packets across {window.DistinctPorts.Count} ports from one source",
                Build());
        }

        if (window.IcmpCount >= _icmpFloodPackets)
        {
            return PreFilterResult.KnownAttack(AttackTypes.DoS,
                $"ICMP flood: {window.IcmpCount} ICMP packets from one source", Build());
        }

        if (window.TotalPackets >= _floodPackets)
        {
            return PreFilterResult.KnownAttack(AttackTypes.DoS,
                $"Packet flood: {window.TotalPackets} packets from one source", Build());
        }

        if (window.DistinctDestinationIps.Count >= _hostSweepDistinctIps &&
            window.DistinctPorts.Count <= 2 &&
            window.TotalPackets <= window.DistinctDestinationIps.Count * 2)
        {
            return PreFilterResult.KnownAttack(AttackTypes.PortScan,
                $"Host sweep: {window.DistinctDestinationIps.Count} hosts probed from one source", Build());
        }

        if (window.DistinctPorts.Count >= _portScanDistinctPorts &&
            window.TotalPackets <= window.DistinctPorts.Count * _portScanMaxPacketsPerPort)
        {
            return PreFilterResult.KnownAttack(AttackTypes.PortScan,
                $"Port scan: {window.DistinctPorts.Count} distinct ports from one source", Build());
        }

        if (window.AuthConnections >= _bruteForceConnections &&
            window.TotalPackets <= window.AuthConnections * _bruteForceMaxPacketsPerAttempt)
        {
            string service = window.LastAuthPort == 22 ? "SSH" : "FTP";
            return PreFilterResult.KnownAttack(AttackTypes.BruteForce,
                $"{service} brute force: {window.AuthConnections} connections from one source", Build());
        }

        if (window.SynCount >= _synFloodSyns && window.AckCount == 0)
        {
            return PreFilterResult.KnownAttack(AttackTypes.DoS,
                $"TCP SYN flood: {window.SynCount} SYNs from one source", Build());
        }

        return null;
    }

    private readonly record struct ScanEntry(int Packets, DateTime LastSeen);

    private sealed class ScanWindow
    {
        public readonly Dictionary<int, ScanEntry> Ports = new();
        public readonly Dictionary<string, ScanEntry> Hosts = new();
        public DateTime LastPrunedAt;
        public DateTime LastSeen;
    }

    private sealed class SourceWindow
    {
        private readonly List<(DateTime Timestamp, string DestinationIp, int Port, bool IsSyn, bool IsRst, bool IsAck, byte Protocol)> _observations = new();

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
            _observations.Add((packet.Timestamp, packet.DestinationIp, packet.DestinationPort, packet.IsSyn, packet.IsRst, packet.IsAck, packet.Protocol));
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
            window.TotalSeconds);

        private void Recompute()
        {
            DistinctPorts.Clear();
            DistinctDestinationIps.Clear();
            AuthConnections = 0;
            SynCount = 0;
            AckCount = 0;
            IcmpCount = 0;
            TotalPackets = _observations.Count;

            foreach (var (_, destinationIp, port, isSyn, _, isAck, protocol) in _observations)
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
                else if (isAck)
                {
                    AckCount++;
                }
            }
        }
    }
}

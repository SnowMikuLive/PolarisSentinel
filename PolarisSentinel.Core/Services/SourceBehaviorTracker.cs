using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Services;

// One observed packet, reduced to the fields behavioral detection needs. Kept free of
// capture-library types so the tracker is pure domain logic.
public readonly record struct PacketObservation(
    string SourceIp,
    string DestinationIp,
    int DestinationPort,
    byte Protocol,
    bool IsSyn,
    bool IsRst,
    int PacketSize,
    DateTime Timestamp);

// Behavioural detection across many flows from the same source IP. A single flow cannot
// reveal a port scan or a brute-force run (each attempt is its own short flow), so this
// tracker keeps a sliding window per source and flags aggregate behaviour instead.
public sealed class SourceBehaviorTracker
{
    // How long an observation stays in the window.
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

    // Global aggregate window, independent of source IP, so a spoofed-source flood
    // (hping3 --rand-source) is caught even though no single source repeats.
    private readonly Queue<DateTime> _globalPackets = new();
    private DateTime _globalLastFlaggedAt = DateTime.MinValue;
    private string _globalLastSource = string.Empty;

    // Cap the tracked sources so a spoofed-source flood cannot grow memory without bound.
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

    // Records one packet against its source's window.
    public void Observe(PacketObservation packet)
    {
        lock (_lock)
        {
            // Global aggregate: every packet counts, regardless of source, so a
            // spoofed-source flood is visible even when no source repeats.
            _globalPackets.Enqueue(packet.Timestamp);
            _globalLastSource = packet.SourceIp;
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

    // Fast-path check run on every packet. Returns a verdict the moment a source (or the
    // global aggregate) crosses a flood threshold, so blocking does not wait for the flow
    // to go idle. Returns null when nothing has crossed a threshold yet.
    public PreFilterResult? EvaluateFast(PacketObservation packet)
    {
        lock (_lock)
        {
            // Global flood first: a random/spoofed-source flood shows up here but not in
            // any single source's window.
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
            if (verdict is null)
            {
                return null;
            }

            if (packet.Timestamp - window.LastFlaggedAt < _cooldown)
            {
                return null;
            }

            window.LastFlaggedAt = packet.Timestamp;
            return verdict;
        }
    }

    // Drops observations outside the window from the global aggregate.
    private void TrimGlobal(DateTime now)
    {
        DateTime cutoff = now - _window;
        while (_globalPackets.Count > 0 && _globalPackets.Peek() < cutoff)
        {
            _globalPackets.Dequeue();
        }
    }

    // Evaluates the current window for a source and returns a known-attack verdict when the
    // aggregate behaviour matches a scan, brute-force run, or flood. Returns null otherwise.
    // A source that was just flagged is suppressed for a cooldown so one attack does not
    // raise an alert for every expiring flow it produced.
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
            if (verdict is null)
            {
                return null;
            }

            // Suppress repeats within the cooldown; the source stays tracked so the
            // window keeps accumulating and re-fires after the cooldown if it persists.
            if (now - window.LastFlaggedAt < _cooldown)
            {
                return null;
            }

            window.LastFlaggedAt = now;
            return verdict;
        }
    }

    // Drops windows that have been empty for a while, so the tracker does not leak.
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
        // Volume-based flood rules run first: a high packet count is stronger evidence of a
        // DoS than the port spread, and a multi-port flood would otherwise be mislabelled
        // as a port scan (it touches many ports too).

        // Multi-port DoS: one source blasting a high packet volume spread across many
        // ports (hping3 --flood to a port range). Each port is its own short flow, so the
        // per-flow pre-filter never sees it; the aggregate packet count does.
        if (window.TotalPackets >= _floodPackets && window.DistinctPorts.Count >= _floodDistinctPorts)
        {
            return PreFilterResult.KnownAttack(
                AttackTypes.DoS,
                $"Multi-port flood: {window.TotalPackets} packets across {window.DistinctPorts.Count} ports from one source");
        }

        // ICMP flood: one source emitting a sustained burst of ICMP packets (ping flood or
        // echo-request storm). ICMP has no ports, so the packet count is the only signal;
        // the threshold is lower than the TCP/UDP floods because a single ping stream is
        // enough to saturate a link.
        if (window.IcmpCount >= _icmpFloodPackets)
        {
            return PreFilterResult.KnownAttack(
                AttackTypes.DoS,
                $"ICMP flood: {window.IcmpCount} ICMP packets from one source");
        }

        // Generic single-source packet flood: a high total packet count from one source,
        // regardless of protocol or port spread, catches floods the signatures above miss.
        if (window.TotalPackets >= _floodPackets)
        {
            return PreFilterResult.KnownAttack(
                AttackTypes.DoS,
                $"Packet flood: {window.TotalPackets} packets from one source");
        }

        // Port scan: one source touching many distinct destination ports in the window
        // without the packet volume of a flood.
        if (window.DistinctPorts.Count >= _portScanDistinctPorts)
        {
            return PreFilterResult.KnownAttack(
                AttackTypes.PortScan,
                $"Port scan: {window.DistinctPorts.Count} distinct ports from one source");
        }

        // Brute force: many new connections to an authentication port in the window.
        if (window.AuthConnections >= _bruteForceConnections)
        {
            string service = window.LastAuthPort == 22 ? "SSH" : "FTP";
            return PreFilterResult.KnownAttack(
                AttackTypes.BruteForce,
                $"{service} brute force: {window.AuthConnections} connections from one source");
        }

        // SYN flood: many half-open SYNs with no handshake completion.
        if (window.SynCount >= 100 && window.AckCount == 0)
        {
            return PreFilterResult.KnownAttack(
                AttackTypes.DoS,
                $"TCP SYN flood: {window.SynCount} SYNs from one source");
        }

        return null;
    }

    // Per-source sliding-window counters.
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

        // When this source was last flagged, for the alert cooldown.
        public DateTime LastFlaggedAt { get; set; } = DateTime.MinValue;

        public void Add(PacketObservation packet, TimeSpan window)
        {
            LastSeen = packet.Timestamp;
            _observations.Add((packet.Timestamp, packet.DestinationIp, packet.DestinationPort, packet.IsSyn, packet.IsRst, packet.Protocol));

            // Recompute the aggregate counters from the pruned window.
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

                    // A new connection to an authentication port counts as one brute-force attempt.
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

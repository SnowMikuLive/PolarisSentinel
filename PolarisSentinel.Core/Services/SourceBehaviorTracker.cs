using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Services;

// One observed packet, reduced to the fields behavioral detection needs. Kept free of
// capture-library types so the tracker is pure domain logic.
public readonly record struct PacketObservation(
    string SourceIp,
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
    private readonly TimeSpan _cooldown;

    private readonly object _lock = new();
    private readonly Dictionary<string, SourceWindow> _sources = new();

    // Cap the tracked sources so a spoofed-source flood cannot grow memory without bound.
    private const int MaxTrackedSources = 50000;

    public SourceBehaviorTracker(
        TimeSpan window,
        int portScanDistinctPorts = 8,
        int bruteForceConnections = 5,
        TimeSpan? cooldown = null,
        int icmpFloodPackets = 50)
    {
        _window = window;
        _portScanDistinctPorts = portScanDistinctPorts;
        _bruteForceConnections = bruteForceConnections;
        _cooldown = cooldown ?? TimeSpan.FromSeconds(30);
        _icmpFloodPackets = icmpFloodPackets;
    }

    // Records one packet against its source's window.
    public void Observe(PacketObservation packet)
    {
        lock (_lock)
        {
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
        // Port scan: one source touching many distinct destination ports in the window.
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

        return null;
    }

    // Per-source sliding-window counters.
    private sealed class SourceWindow
    {
        private readonly List<(DateTime Timestamp, int Port, bool IsSyn, bool IsRst, byte Protocol)> _observations = new();

        public HashSet<int> DistinctPorts { get; } = new();
        public int AuthConnections { get; private set; }
        public int LastAuthPort { get; private set; }
        public int SynCount { get; private set; }
        public int AckCount { get; private set; }
        public int IcmpCount { get; private set; }
        public DateTime LastSeen { get; private set; }

        // When this source was last flagged, for the alert cooldown.
        public DateTime LastFlaggedAt { get; set; } = DateTime.MinValue;

        public void Add(PacketObservation packet, TimeSpan window)
        {
            LastSeen = packet.Timestamp;
            _observations.Add((packet.Timestamp, packet.DestinationPort, packet.IsSyn, packet.IsRst, packet.Protocol));

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
            AuthConnections = 0;
            SynCount = 0;
            AckCount = 0;
            IcmpCount = 0;

            foreach (var (_, port, isSyn, _, protocol) in _observations)
            {
                DistinctPorts.Add(port);

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

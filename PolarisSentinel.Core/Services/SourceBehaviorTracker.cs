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
    DateTime Timestamp,
    bool IsInbound = true);

// Detects aggregate behaviour across many short flows from one source (port scans,
// brute-force runs, floods) that a single flow cannot reveal. Also tracks a global
// packet rate so a spoofed/random-source flood is still caught.
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

    // Probes seen from each source, kept over a horizon long enough to cover a port range
    // walked slowly. Separate from the volume window so a scan spread over a minute is not
    // forgotten between windows.
    private readonly Dictionary<string, ScanWindow> _scans = new();

    // Global window of every observed packet, so a flood spread across many spoofed sources
    // (where no single source window accumulates) is still visible. Each entry keeps its
    // source IP so the rule can require genuine source diversity, not just raw volume.
    private readonly Queue<(DateTime Timestamp, string SourceIp)> _globalPackets = new();
    private readonly Dictionary<string, int> _globalSourceCounts = new();
    private DateTime _globalLastFlaggedAt = DateTime.MinValue;

    private const int MaxTrackedSources = 50000;
    private const int MaxScanEntries = 4096;
    private const int MaxPacketsPerProbedHost = 2;
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
        _scanWindow = scanWindow ?? TimeSpan.FromMinutes(1);
    }

    public void Observe(PacketObservation packet)
    {
        // Only traffic aimed at this host is analysed. The host's own outbound connections
        // would otherwise read as scans and floods aimed at the remote side.
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

    // Records a probe against its destination port and host. Only SYNs and ICMP echo
    // requests count: the scanned host answers each probe, so counting replies would make
    // the victim look like the scanner.
    private void ObserveProbe(PacketObservation packet)
    {
        if (!packet.IsSyn && packet.Protocol != ProtocolNumbers.Icmp)
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

    // Counts a probe against a key, without letting a fast scan grow the map without bound.
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

    // Drops probes that fell out of the scan window. Throttled because it walks the maps.
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

    // Per-packet check that returns a verdict the moment a threshold is crossed.
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
        // The snapshot is only built for the verdict that actually fires, so the per-packet
        // fast-path does not allocate on every observation.
        BehaviorWindowStats Build() => window.Snapshot(_window);

        // Scan rules come first, because they are the more specific signature: a scan crosses
        // the volume thresholds too, and would otherwise be reported as a generic flood.
        // Only ports that were probed once or twice count, which is what separates a scanner
        // walking a port range from a client that holds real sessions on the ports it uses.
        int probedPorts = scan is null ? 0 : scan.Ports.Count(kv => kv.Value.Packets <= _portScanMaxPacketsPerPort);
        if (probedPorts >= _portScanDistinctPorts)
        {
            return PreFilterResult.KnownAttack(AttackTypes.PortScan,
                $"Port scan: {probedPorts} ports probed from one source", Build());
        }

        // The same test horizontally: a sweep probes many hosts a packet or two each.
        int probedHosts = scan is null ? 0 : scan.Hosts.Count(kv => kv.Value.Packets <= MaxPacketsPerProbedHost);
        if (probedHosts >= _hostSweepDistinctIps)
        {
            return PreFilterResult.KnownAttack(AttackTypes.PortScan,
                $"Host sweep: {probedHosts} hosts probed from one source", Build());
        }

        // Volume rules: a high packet count is stronger evidence than port spread, and a
        // multi-port flood would otherwise be mislabelled as a port scan.
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

        // Horizontal sweep: one source probing many hosts on the same port (or two). The
        // packets-per-host guard keeps ordinary fan-out (a few packets per host) distinct
        // from a sweep, which fires a single probe at each target.
        if (window.DistinctDestinationIps.Count >= _hostSweepDistinctIps &&
            window.DistinctPorts.Count <= 2 &&
            window.TotalPackets <= window.DistinctDestinationIps.Count * 2)
        {
            return PreFilterResult.KnownAttack(AttackTypes.PortScan,
                $"Host sweep: {window.DistinctDestinationIps.Count} hosts probed from one source", Build());
        }

        // Port scan: many distinct destination ports, each probed with only a handful of
        // packets. The packets-per-port guard stops a client with several real sessions
        // (many packets per port) from being mistaken for a scanner.
        if (window.DistinctPorts.Count >= _portScanDistinctPorts &&
            window.TotalPackets <= window.DistinctPorts.Count * _portScanMaxPacketsPerPort)
        {
            return PreFilterResult.KnownAttack(AttackTypes.PortScan,
                $"Port scan: {window.DistinctPorts.Count} distinct ports from one source", Build());
        }

        // Brute force: repeated new connections to an authentication port, each a small
        // number of packets. Long-lived legitimate sessions send far more packets per
        // connection, so the packets-per-attempt guard keeps them out of this rule.
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

    // One probed port or host: how many probes hit it, and when the last one arrived.
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

using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Services;

// One observed packet, reduced to what behavioural detection needs.
// IsAck must be filled in by the capture layer: it separates SYN-ACK replies and
// established traffic from real probes.
public readonly record struct PacketObservation(
    string SourceIp,
    string DestinationIp,
    int DestinationPort,
    byte Protocol,
    bool IsSyn,
    bool IsRst,
    int PacketSize,
    DateTime Timestamp,
    bool IsAck = false);

// Detects aggregate behaviour across many short flows from one source (port scans,
// brute-force runs, floods) that a single flow cannot reveal. Also tracks a global
// packet rate so a spoofed/random-source flood is still caught.
public sealed class SourceBehaviorTracker
{
    private const int MaxTrackedSources = 50000;
    private const int MaxFastObservations = 50000;
    private const int MaxSlowObservations = 20000;
    private const int SynFloodPackets = 100;
    private const int PureAckMaxSize = 100;
    private const int UdpProbeMaxPort = 32767;
    private const byte TcpProtocol = 6;

    private readonly TimeSpan _window;
    private readonly TimeSpan _slowWindow;
    private readonly TimeSpan _cooldown;
    private readonly int _portScanDistinctPorts;
    private readonly int _slowPortScanDistinctPorts;
    private readonly int _sweepDistinctHosts;
    private readonly int _slowSweepDistinctHosts;
    private readonly int _bruteForceConnections;
    private readonly int _slowBruteForceConnections;
    private readonly int _connectionFloodConnections;
    private readonly int _icmpFloodPackets;
    private readonly int _floodPackets;
    private readonly int _floodDistinctPorts;
    private readonly int _globalFloodPackets;

    private readonly object _lock = new();
    private readonly Dictionary<string, SourceWindow> _sources = new();

    private readonly SecondRing _global;
    private DateTime _globalLastFlaggedAt = DateTime.MinValue;

    public SourceBehaviorTracker(
        TimeSpan window,
        int portScanDistinctPorts = 8,
        int bruteForceConnections = 5,
        TimeSpan? cooldown = null,
        int icmpFloodPackets = 50,
        int floodPackets = 200,
        int floodDistinctPorts = 20,
        int globalFloodPackets = 1000,
        TimeSpan? slowWindow = null,
        int slowPortScanDistinctPorts = 25,
        int slowBruteForceConnections = 15,
        int sweepDistinctHosts = 16,
        int slowSweepDistinctHosts = 40,
        int connectionFloodConnections = 300)
    {
        _window = window;
        var slow = slowWindow ?? TimeSpan.FromMinutes(10);
        _slowWindow = slow < window ? window : slow;
        _cooldown = cooldown ?? TimeSpan.FromSeconds(30);
        _portScanDistinctPorts = portScanDistinctPorts;
        _slowPortScanDistinctPorts = slowPortScanDistinctPorts;
        _sweepDistinctHosts = sweepDistinctHosts;
        _slowSweepDistinctHosts = slowSweepDistinctHosts;
        _bruteForceConnections = bruteForceConnections;
        _slowBruteForceConnections = slowBruteForceConnections;
        _connectionFloodConnections = connectionFloodConnections;
        _icmpFloodPackets = icmpFloodPackets;
        _floodPackets = floodPackets;
        _floodDistinctPorts = floodDistinctPorts;
        _globalFloodPackets = globalFloodPackets;
        _global = new SecondRing(Math.Max(1, (int)Math.Ceiling(window.TotalSeconds)));
    }

    public void Observe(PacketObservation packet)
    {
        var obs = ToObs(packet);

        lock (_lock)
        {
            // Only packets that open something count towards the global rate, so bulk
            // TCP transfers do not look like a flood.
            if (obs.Syn || obs.Protocol == ProtocolNumbers.Udp || obs.Protocol == ProtocolNumbers.Icmp)
            {
                _global.Add(packet.Timestamp);
            }

            if (!_sources.TryGetValue(packet.SourceIp, out var window))
            {
                if (_sources.Count >= MaxTrackedSources)
                {
                    MakeRoom(packet.Timestamp);
                }

                window = new SourceWindow(_window, _slowWindow);
                _sources[packet.SourceIp] = window;
            }

            window.Add(obs);
        }
    }

    // Per-packet check that returns a verdict the moment a threshold is crossed.
    public PreFilterResult? EvaluateFast(PacketObservation packet)
    {
        lock (_lock)
        {
            int global = _global.Sum(packet.Timestamp);
            if (global >= _globalFloodPackets &&
                packet.Timestamp - _globalLastFlaggedAt >= _cooldown)
            {
                _globalLastFlaggedAt = packet.Timestamp;
                return PreFilterResult.SpoofedFlood(
                    AttackTypes.DoS,
                    $"Global flood: {global} packets in {_window.TotalSeconds:0}s across many sources");
            }

            if (!_sources.TryGetValue(packet.SourceIp, out var window))
            {
                return null;
            }

            return Classify(packet.SourceIp, window, ToObs(packet), false, packet.Timestamp);
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

            return Classify(sourceIp, window, default, true, now);
        }
    }

    public void Prune(DateTime now)
    {
        lock (_lock)
        {
            RemoveStale(now);
        }
    }

    private void RemoveStale(DateTime now)
    {
        var stale = _sources
            .Where(kv => now - kv.Value.LastSeen > _slowWindow)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var ip in stale)
        {
            _sources.Remove(ip);
        }
    }

    // Called when the table is full. Evicts the least recently active sources instead of
    // ignoring new ones, otherwise spoofed sources could fill the table and hide the real attacker.
    private void MakeRoom(DateTime now)
    {
        RemoveStale(now);
        if (_sources.Count < MaxTrackedSources)
        {
            return;
        }

        var idle = _sources
            .OrderBy(kv => kv.Value.LastSeen)
            .Take(MaxTrackedSources / 20)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var ip in idle)
        {
            _sources.Remove(ip);
        }
    }

    private static Obs ToObs(PacketObservation p)
    {
        bool tcp = p.Protocol == TcpProtocol;

        // A SYN-ACK is the server answering, only the initiator's SYN is a connection attempt.
        bool syn = tcp && p.IsSyn && !p.IsAck;
        bool established = tcp && !p.IsSyn && !p.IsRst;

        // SYN, FIN, NULL and Xmas probes never carry ACK; replies and data do.
        bool probe = tcp
            ? !p.IsAck && !p.IsRst
            : p.Protocol == ProtocolNumbers.Udp && p.DestinationPort <= UdpProbeMaxPort;

        bool smallAck = established && p.PacketSize <= PureAckMaxSize;

        return new Obs(p.Timestamp, p.DestinationIp ?? string.Empty, p.DestinationPort, p.Protocol,
            syn, probe, established, smallAck);
    }

    private PreFilterResult? Classify(string sourceIp, SourceWindow w, Obs touched, bool full, DateTime now)
    {
        var c = w.Fast;

        // Volume rules first: a flood would otherwise be mislabelled as a port scan.
        // A scan touches many ports about once each, a flood repeats itself.
        int volume = c.Syn + c.Udp + c.SmallAck;
        if (volume >= _floodPackets &&
            c.PortHosts.Count >= _floodDistinctPorts &&
            volume >= c.PortRefs.Count * 5 &&
            w.TryFlag("flood:multiport", now, _cooldown))
        {
            return Known(AttackTypes.DoS,
                $"Multi-port flood: {volume} packets across {c.PortHosts.Count} ports from one source", c, _window);
        }

        if (c.Syn >= SynFloodPackets &&
            c.Established * 5 <= c.Syn &&
            c.Syn >= c.PortRefs.Count * 3 &&
            w.TryFlag("flood:syn", now, _cooldown))
        {
            return Known(AttackTypes.DoS, $"TCP SYN flood: {c.Syn} SYNs from one source", c, _window);
        }

        int udp = Peak(c.UdpHost, full, touched.Host, out var udpHost);
        if (udp >= _floodPackets &&
            IsOneWay(sourceIp, c, udpHost) &&
            w.TryFlag("flood:udp", now, _cooldown))
        {
            return Known(AttackTypes.DoS, $"UDP flood: {udp} packets to {udpHost} from one source", c, _window);
        }

        int acks = Peak(c.AckHost, full, touched.Host, out var ackHost);
        if (acks >= _floodPackets &&
            IsOneWay(sourceIp, c, ackHost) &&
            w.TryFlag("flood:ack", now, _cooldown))
        {
            return Known(AttackTypes.DoS, $"TCP ACK flood: {acks} payload-less ACKs to {ackHost} from one source", c, _window);
        }

        int icmp = Peak(c.IcmpHost, full, touched.Host, out var icmpHost);
        if (icmp >= _icmpFloodPackets && w.TryFlag("flood:icmp", now, _cooldown))
        {
            return Known(AttackTypes.DoS, $"ICMP flood: {icmp} ICMP packets to {icmpHost} from one source", c, _window);
        }

        // Completed connections at a high rate: application-layer floods never show up
        // as half-open SYNs.
        int conns = Peak(c.Conns, full, (touched.Host, touched.Port), out var connKey);
        if (conns >= _connectionFloodConnections && w.TryFlag("flood:conn", now, _cooldown))
        {
            return Known(AttackTypes.DoS,
                $"Connection flood: {conns} connections to {connKey.Host}:{connKey.Port} from one source", c, _window);
        }

        var verdict = CheckProbing(w, c, touched, full, now,
            _portScanDistinctPorts, _sweepDistinctHosts, _bruteForceConnections, _window, false);

        if (verdict is null && _slowWindow > _window)
        {
            verdict = CheckProbing(w, w.Slow, touched, full, now,
                _slowPortScanDistinctPorts, _slowSweepDistinctHosts, _slowBruteForceConnections, _slowWindow, true);
        }

        return verdict;
    }

    // Port scan, port sweep and brute force share the same counters in the fast and slow windows.
    private PreFilterResult? CheckProbing(
        SourceWindow w, WindowCounters c, Obs touched, bool full, DateTime now,
        int portLimit, int sweepLimit, int authLimit, TimeSpan span, bool slow)
    {
        // Many distinct ports on one host.
        int ports = Peak(c.HostPorts, full, touched.Host, out var scanHost);
        if (ports >= portLimit && w.TryFlag("scan:ports", now, _cooldown))
        {
            return Known(AttackTypes.PortScan,
                Name(slow, $"Port scan: {ports} distinct ports on {scanHost} from one source"), c, span);
        }

        // The same port on many hosts.
        int hosts = Peak(c.PortHosts, full, touched.Port, out var sweepPort);
        if (hosts >= sweepLimit && w.TryFlag("scan:hosts", now, _cooldown))
        {
            return Known(AttackTypes.PortScan,
                Name(slow, $"Port sweep: port {sweepPort} on {hosts} hosts from one source"), c, span);
        }

        // New connections to the authentication port of one host. SSH and FTP are counted
        // separately.
        int auth = Peak(c.Auth, full, (touched.Host, touched.Port), out var authKey);
        if (auth >= authLimit && w.TryFlag($"brute:{authKey.Port}", now, _cooldown))
        {
            string service = authKey.Port == 22 ? "SSH" : "FTP";
            return Known(AttackTypes.BruteForce,
                Name(slow, $"{service} brute force: {auth} connections to {authKey.Host} from one source"), c, span);
        }

        return null;
    }

    private static string Name(bool slow, string text) =>
        slow ? $"Slow {char.ToLowerInvariant(text[0])}{text[1..]}" : text;

    // True when the target sent (almost) nothing back to this source in the window. The peer's
    // own window holds exactly that count.
    private bool IsOneWay(string sourceIp, WindowCounters c, string host)
    {
        int sent = c.HostRefs.TryGetValue(host, out var s) ? s : 0;
        int back = _sources.TryGetValue(host, out var peer) && peer.Fast.HostRefs.TryGetValue(sourceIp, out var r) ? r : 0;
        return back * 10 <= sent;
    }

    // Incremental mode checks only the entry the current packet touched; full mode scans the lot.
    private static int Peak<TKey>(Dictionary<TKey, int> map, bool full, TKey touched, out TKey at)
        where TKey : notnull
    {
        at = touched;

        if (!full)
        {
            return map.TryGetValue(touched, out var n) ? n : 0;
        }

        int best = 0;
        foreach (var kv in map)
        {
            if (kv.Value > best)
            {
                best = kv.Value;
                at = kv.Key;
            }
        }

        return best;
    }

    private static PreFilterResult Known(string attackType, string description, WindowCounters c, TimeSpan span) =>
        PreFilterResult.KnownAttack(attackType, description, Snapshot(c, span));

    private static BehaviorWindowStats Snapshot(WindowCounters c, TimeSpan span) => new(
        c.Total,
        c.PortHosts.Count,
        c.HostRefs.Count,
        c.Syn,
        c.Established,
        c.Icmp,
        c.AuthTotal,
        span.TotalSeconds,
        c.PortHosts.Keys.OrderBy(p => p).Take(1000).ToList());

    private readonly record struct Obs(
        DateTime Time,
        string Host,
        int Port,
        byte Protocol,
        bool Syn,
        bool Probe,
        bool Established,
        bool SmallAck);

    private sealed class SourceWindow
    {
        private Dictionary<string, DateTime>? _flagged;

        public SourceWindow(TimeSpan fast, TimeSpan slow)
        {
            Fast = new WindowCounters(fast, MaxFastObservations);
            Slow = new WindowCounters(slow, MaxSlowObservations);
        }

        public WindowCounters Fast { get; }
        public WindowCounters Slow { get; }
        public DateTime LastSeen { get; private set; } = DateTime.MinValue;

        public void Add(Obs o)
        {
            if (o.Time > LastSeen)
            {
                LastSeen = o.Time;
            }

            Fast.Add(o);

            // The slow window only needs the packets that matter for scans and brute force.
            if (o.Probe || o.Syn)
            {
                Slow.Add(o);
            }

            Fast.Trim(LastSeen);
            Slow.Trim(LastSeen);
        }

        // Cooldown is tracked per attack type, so a scan followed by a brute force from
        // the same source still raises both alerts.
        public bool TryFlag(string key, DateTime now, TimeSpan cooldown)
        {
            _flagged ??= new Dictionary<string, DateTime>();

            if (_flagged.TryGetValue(key, out var last) && now - last < cooldown)
            {
                return false;
            }

            _flagged[key] = now;
            return true;
        }
    }

    // A sliding window whose counters are updated incrementally on add and expiry.
    private sealed class WindowCounters
    {
        private readonly TimeSpan _span;
        private readonly int _capacity;
        private readonly List<Obs> _items = new();
        private int _head;

        public WindowCounters(TimeSpan span, int capacity)
        {
            _span = span;
            _capacity = capacity;
        }

        public int Total { get; private set; }
        public int Syn { get; private set; }
        public int Established { get; private set; }
        public int SmallAck { get; private set; }
        public int Udp { get; private set; }
        public int Icmp { get; private set; }
        public int AuthTotal { get; private set; }

        // Packets sent to each destination host.
        public Dictionary<string, int> HostRefs { get; } = new();

        // Probe packets per (host, port), distinct ports per host, distinct hosts per port.
        public Dictionary<(string Host, int Port), int> PortRefs { get; } = new();
        public Dictionary<string, int> HostPorts { get; } = new();
        public Dictionary<int, int> PortHosts { get; } = new();

        // New connections per (host, port); authentication ports are kept apart.
        public Dictionary<(string Host, int Port), int> Auth { get; } = new();
        public Dictionary<(string Host, int Port), int> Conns { get; } = new();

        public Dictionary<string, int> UdpHost { get; } = new();
        public Dictionary<string, int> IcmpHost { get; } = new();
        public Dictionary<string, int> AckHost { get; } = new();

        public void Add(Obs o)
        {
            _items.Add(o);
            Apply(o, 1);
        }

        public void Trim(DateTime now)
        {
            var cutoff = now.Ticks > _span.Ticks ? now - _span : DateTime.MinValue;

            while (_head < _items.Count &&
                   (_items[_head].Time < cutoff || _items.Count - _head > _capacity))
            {
                Apply(_items[_head], -1);
                _head++;
            }

            if (_head >= 1024 && _head * 2 >= _items.Count)
            {
                _items.RemoveRange(0, _head);
                _head = 0;
            }
        }

        private void Apply(Obs o, int delta)
        {
            Total += delta;
            Adjust(HostRefs, o.Host, delta);

            if (o.Protocol == ProtocolNumbers.Icmp)
            {
                Icmp += delta;
                Adjust(IcmpHost, o.Host, delta);
            }
            else if (o.Protocol == ProtocolNumbers.Udp)
            {
                Udp += delta;
                Adjust(UdpHost, o.Host, delta);
            }

            if (o.Syn)
            {
                Syn += delta;

                if (o.Port == 22 || o.Port == 21)
                {
                    AuthTotal += delta;
                    Adjust(Auth, (o.Host, o.Port), delta);
                }
                else
                {
                    Adjust(Conns, (o.Host, o.Port), delta);
                }
            }

            if (o.Established)
            {
                Established += delta;
            }

            if (o.SmallAck)
            {
                SmallAck += delta;
                Adjust(AckHost, o.Host, delta);
            }

            if (o.Probe)
            {
                var key = (o.Host, o.Port);
                PortRefs.TryGetValue(key, out int before);
                int after = Adjust(PortRefs, key, delta);

                if (before == 0 && after > 0)
                {
                    Adjust(HostPorts, o.Host, 1);
                    Adjust(PortHosts, o.Port, 1);
                }
                else if (before > 0 && after == 0)
                {
                    Adjust(HostPorts, o.Host, -1);
                    Adjust(PortHosts, o.Port, -1);
                }
            }
        }

        private static int Adjust<TKey>(Dictionary<TKey, int> map, TKey key, int delta) where TKey : notnull
        {
            int next = (map.TryGetValue(key, out var current) ? current : 0) + delta;

            if (next <= 0)
            {
                map.Remove(key);
                return 0;
            }

            map[key] = next;
            return next;
        }
    }

    // Packet counts per second over a fixed number of seconds. Keeps the global rate
    // cheap no matter how many packets arrive.
    private sealed class SecondRing
    {
        private readonly long[] _seconds;
        private readonly int[] _counts;

        public SecondRing(int size)
        {
            _seconds = new long[size];
            _counts = new int[size];
            Array.Fill(_seconds, -1L);
        }

        public void Add(DateTime time)
        {
            long second = time.Ticks / TimeSpan.TicksPerSecond;
            int index = (int)(second % _seconds.Length);

            if (_seconds[index] != second)
            {
                _seconds[index] = second;
                _counts[index] = 0;
            }

            _counts[index]++;
        }

        public int Sum(DateTime time)
        {
            long now = time.Ticks / TimeSpan.TicksPerSecond;
            long from = now - _seconds.Length + 1;
            int sum = 0;

            for (int i = 0; i < _seconds.Length; i++)
            {
                if (_seconds[i] >= from && _seconds[i] <= now)
                {
                    sum += _counts[i];
                }
            }

            return sum;
        }
    }
}
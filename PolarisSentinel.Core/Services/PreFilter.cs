using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Services;

// Rule-based pre-filter: detects attack signatures, drops obvious noise, and forwards
// the rest to the AI engine. Single-flow signatures are reported as Suspicious (not
// KnownAttack) because the per-flow thresholds are low enough to trip on legitimate
// traffic; only the cross-flow SourceBehaviorTracker escalates straight to KnownAttack.
public sealed class PreFilter
{
    // Ports that legitimately carry one-way traffic (DHCP, NTP, NetBIOS, SSDP, mDNS).
    private static readonly HashSet<int> OneWayBenignPorts = new() { 67, 68, 123, 137, 138, 1900, 5353 };

    private readonly int _minPacketsForAnalysis;

    public PreFilter(int minPacketsForAnalysis)
    {
        _minPacketsForAnalysis = minPacketsForAnalysis;
    }

    // Classifies a finished flow as known attack, suspicious (for the AI engine), or normal.
    public PreFilterResult Classify(FlowStatistics flow)
    {
        if (flow.TotalPackets < _minPacketsForAnalysis)
            return PreFilterResult.Normal();

        // The flow key orders endpoints by IP string, so normalise the dominant sender forward.
        var direction = Normalise(flow);

        // Attack signatures run before the benign filters: floods can be short-lived.
        var attack = DetectFlood(direction) ?? DetectScan(direction) ?? DetectBruteForce(direction);
        if (attack is not null)
            return attack;

        // Short-lived flow, likely a handshake fragment.
        if (flow.DurationSeconds < 0.1)
            return PreFilterResult.Normal();

        if (direction.FwdPackets == 0)
            return PreFilterResult.Normal();

        // No reply at all is also what scans and floods look like, so only known
        // one-way protocols are dropped here.
        if (direction.BwdPackets == 0)
        {
            return OneWayBenignPorts.Contains(direction.DestinationPort)
                ? PreFilterResult.Normal()
                : PreFilterResult.Suspicious("Unidirectional flow without replies forwarded to the AI engine.");
        }

        double rate = ForwardRate(direction);
        bool isWebPort = direction.DestinationPort == 80 || direction.DestinationPort == 443;

        // Slowloris / slow POST: long-lived, tiny packets, very low rate. This would
        // otherwise pass as ordinary two-way traffic below.
        bool isSlowHttp =
            (isWebPort || direction.DestinationPort == 8080) &&
            direction.DurationSeconds > 10.0 &&
            direction.FwdPackets >= 3 &&
            direction.PacketSizeMean < 100 &&
            rate < 2.0;

        if (isSlowHttp)
            return PreFilterResult.Suspicious("Possible slow HTTP attack forwarded to the AI engine.");

        double downUp = (double)direction.BwdBytes / Math.Max(direction.FwdBytes, 1);

        bool isNormalWebTraffic =
            isWebPort &&
            direction.FwdPackets > 5 &&
            direction.BwdPackets > 5 &&
            direction.SynCount <= 1 &&
            direction.RstCount == 0 &&
            direction.FinCount <= 2 &&
            downUp > 0.1 &&
            downUp < 10 &&
            rate < 500;

        if (isNormalWebTraffic)
            return PreFilterResult.Normal();

        // A long SSH/FTP flow with flat packet sizes is a brute-force run inside one
        // connection, not an ordinary session.
        bool isAuthPort = direction.DestinationPort == 22 || direction.DestinationPort == 21;
        if (isAuthPort &&
            direction.FwdPackets > 10 &&
            direction.PacketSizeMean > 0 &&
            direction.PacketSizeStdDev < 10)
        {
            return PreFilterResult.Suspicious("Flat repeating traffic on an authentication port forwarded to the AI engine.");
        }

        bool isOrdinaryTwoWayTraffic =
            direction.DurationSeconds > 1.0 &&
            direction.SynCount <= 1;

        if (isOrdinaryTwoWayTraffic)
            return PreFilterResult.Normal();

        // Every rule has been evaluated and nothing matched: hand it to the AI engine.
        return PreFilterResult.Suspicious("Suspicious flow forwarded to the AI engine.");
    }

    // Returns the flow as seen from the dominant sender, so the attack rules can
    // assume forward = attacker regardless of how the flow key ordered the endpoints.
    private static FlowStatistics Normalise(FlowStatistics flow)
    {
        if (flow.FwdPackets >= flow.BwdPackets)
        {
            return flow;
        }

        return new FlowStatistics
        {
            Protocol = flow.Protocol,
            DestinationPort = flow.DestinationPort,
            FwdPackets = flow.BwdPackets,
            BwdPackets = flow.FwdPackets,
            FwdBytes = flow.BwdBytes,
            BwdBytes = flow.FwdBytes,
            SynCount = flow.SynCount,
            AckCount = flow.AckCount,
            FinCount = flow.FinCount,
            RstCount = flow.RstCount,
            PshCount = flow.PshCount,
            DurationSeconds = flow.DurationSeconds,
            PacketSizeMean = flow.PacketSizeMean,
            PacketSizeStdDev = flow.PacketSizeStdDev
        };
    }

    // Computed here rather than read from the flow, because Normalise rebuilds the
    // object and does not carry derived rates over.
    private static double ForwardRate(FlowStatistics flow) =>
        flow.FwdPackets / Math.Max(flow.DurationSeconds, 0.05);

    // DoS family: SYN / UDP / ACK / ICMP floods, driven by flag counts and one-way packet volume.
    private PreFilterResult? DetectFlood(FlowStatistics flow)
    {
        bool oneWay = flow.BwdPackets <= flow.FwdPackets * 0.1;
        double rate = ForwardRate(flow);

        // SYN flood: many SYNs and the handshake never completes. The victim may answer
        // with SYN-ACK or RST, so replies are allowed; an established connection would
        // carry far more ACKs than the victim's own replies account for.
        bool isSynFlood =
            flow.SynCount > 10 &&
            flow.AckCount <= flow.BwdPackets + 2;

        if (isSynFlood)
            return Verdict(AttackTypes.DoS, "TCP SYN flood");

        // UDP flood: high one-way UDP packet rate, no reply traffic.
        bool isUdpFlood =
            flow.Protocol == ProtocolNumbers.Udp &&
            oneWay &&
            flow.FwdPackets > 50 &&
            rate > 100;

        if (isUdpFlood)
            return Verdict(AttackTypes.DoS, "UDP flood");

        // ACK flood: fast stream of small ACKs with no SYN. Packet size keeps truncated
        // bulk transfers (which are also all ACKs) from matching.
        bool isAckFlood =
            flow.AckCount > 20 &&
            flow.SynCount == 0 &&
            flow.FwdPackets > flow.BwdPackets * 2 &&
            flow.PacketSizeMean < 100 &&
            rate > 100;

        if (isAckFlood)
            return Verdict(AttackTypes.DoS, "TCP ACK flood");

        // ICMP flood: elevated one-way ICMP packet rate. ICMP has no ports, so thresholds
        // are lower than the TCP/UDP floods.
        bool isIcmpFlood =
            flow.Protocol == ProtocolNumbers.Icmp &&
            flow.FwdPackets > 20 &&
            rate > 25;

        if (isIcmpFlood)
            return Verdict(AttackTypes.DoS, "ICMP flood");

        // ICMP ping flood: many echo requests with a matching reply stream.
        bool isIcmpPingFlood =
            flow.Protocol == ProtocolNumbers.Icmp &&
            flow.FwdPackets > 15 &&
            flow.BwdPackets > 0 &&
            rate > 15 &&
            flow.FwdPackets > flow.BwdPackets;

        if (isIcmpPingFlood)
            return Verdict(AttackTypes.DoS, "ICMP ping flood");

        return null;
    }

    // Port scanning family: SYN / connect / FIN-NULL-Xmas / UDP scans and ICMP sweeps.
    private PreFilterResult? DetectScan(FlowStatistics flow)
    {
        bool shortLived = flow.DurationSeconds < 2.0;
        bool mostlyOutbound = flow.BwdPackets <= flow.FwdPackets * 0.3;

        // SYN scan: closed ports answer each SYN with a RST (so replies are plentiful),
        // filtered ports answer nothing (so the flow is mostly outbound). Either counts.
        bool isSynScan =
            flow.SynCount > 3 &&
            shortLived &&
            (flow.RstCount >= flow.SynCount * 0.5 || mostlyOutbound);

        if (isSynScan)
            return Verdict(AttackTypes.PortScan, "TCP SYN port scan");

        // Connect scan: full handshakes that are reset immediately, no real payload.
        bool isConnectScan =
            flow.SynCount > 3 &&
            flow.AckCount > flow.SynCount &&
            flow.RstCount > 0 &&
            shortLived &&
            flow.PacketSizeMean < 100;

        if (isConnectScan)
            return Verdict(AttackTypes.PortScan, "TCP connect port scan");

        // FIN/NULL/Xmas scan: no SYN at all, only FIN or RST probes. Closed ports answer
        // with RST, so there is no outbound-ratio condition.
        bool isFinNullXmasScan =
            flow.SynCount == 0 &&
            flow.AckCount == 0 &&
            flow.FwdPackets > 3 &&
            (flow.FinCount > 3 || flow.RstCount > 3) &&
            shortLived;

        if (isFinNullXmasScan)
            return Verdict(AttackTypes.PortScan, "FIN/NULL/Xmas port scan");

        // UDP scan: a few small one-way UDP packets to a single port, no replies.
        bool isUdpScan =
            flow.Protocol == ProtocolNumbers.Udp &&
            flow.FwdPackets > 5 &&
            flow.FwdPackets <= 50 &&
            flow.BwdPackets == 0 &&
            flow.PacketSizeMean < 100 &&
            shortLived;

        if (isUdpScan)
            return Verdict(AttackTypes.PortScan, "UDP port scan");

        // ICMP sweep: several one-way echo requests probing hosts (replies suppressed).
        bool isIcmpSweep =
            flow.Protocol == ProtocolNumbers.Icmp &&
            flow.FwdPackets > 3 &&
            flow.FwdPackets <= 50 &&
            flow.BwdPackets <= 1 &&
            shortLived;

        if (isIcmpSweep)
            return Verdict(AttackTypes.PortScan, "ICMP sweep");

        return null;
    }

    // Brute force family: many short connections to SSH/FTP with flat, repeating packet sizes.
    private PreFilterResult? DetectBruteForce(FlowStatistics flow)
    {
        bool isAuthPort = flow.DestinationPort == 22 || flow.DestinationPort == 21;
        if (!isAuthPort)
            return null;

        // Flat traffic: near-constant packet size and a steady connection cadence.
        bool flatTraffic =
            flow.PacketSizeStdDev < 10 &&
            flow.PacketSizeMean > 0;

        bool repeatedAttempts =
            flow.SynCount > 3 &&
            flow.FwdPackets > 5 &&
            flow.PacketSizeMean < 200;

        if (!flatTraffic || !repeatedAttempts)
            return null;

        return flow.DestinationPort == 22
            ? Verdict(AttackTypes.BruteForce, "SSH brute force")
            : Verdict(AttackTypes.BruteForce, "FTP brute force");
    }

    // Single-flow signatures are downgraded to Suspicious: the low per-flow thresholds make
    // them prone to false positives, so the AI engine re-checks before any policy action.
    private static PreFilterResult Verdict(string attackType, string description) =>
        PreFilterResult.Suspicious($"{attackType}: {description}");
}
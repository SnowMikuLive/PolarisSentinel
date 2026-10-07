using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Services;

// Rule-based pre-filter: detects attack signatures, drops obvious noise, and forwards
// the rest to the AI engine. Single-flow signatures are reported as Suspicious (not
// KnownAttack) because the per-flow thresholds are low enough to trip on legitimate
// traffic; only the cross-flow SourceBehaviorTracker escalates straight to KnownAttack.
public sealed class PreFilter
{
    private readonly DetectionThresholds _t;

    public PreFilter(DetectionThresholds thresholds)
    {
        _t = thresholds;
    }

    // Classifies a finished flow as known attack, suspicious (for the AI engine), or normal.
    public PreFilterResult Classify(FlowStatistics flow)
    {
        if (flow.TotalPackets < _t.MinPacketsForAnalysis)
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

        // Unidirectional traffic, typical of broadcast/multicast.
        if (direction.FwdPackets == 0 || direction.BwdPackets == 0)
            return PreFilterResult.Normal();

        bool isNormalWebTraffic =
            (direction.DestinationPort == 443 || direction.DestinationPort == 80) &&
            direction.FwdPackets > 5 &&
            direction.BwdPackets > 5 &&
            direction.SynCount <= 1 &&
            direction.RstCount == 0 &&
            direction.FinCount <= 2 &&
            direction.DownUpRatio > 0.1 &&
            direction.DownUpRatio < 10;

        if (isNormalWebTraffic)
            return PreFilterResult.Normal();

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

    // DoS family: SYN / UDP / ACK / ICMP floods, driven by flag counts and one-way packet volume.
    private PreFilterResult? DetectFlood(FlowStatistics flow)
    {
        bool oneWay = flow.BwdPackets <= flow.FwdPackets * 0.1;

        // SYN flood: many SYNs, no handshake completion, no resets.
        bool isSynFlood =
            flow.SynCount > _t.SynFloodSyns &&
            flow.AckCount == 0 &&
            flow.RstCount == 0 &&
            flow.FwdPackets > flow.BwdPackets * 2;

        if (isSynFlood)
            return Verdict(AttackTypes.DoS, "TCP SYN flood");

        // UDP flood: high one-way UDP packet rate, no reply traffic.
        bool isUdpFlood =
            flow.Protocol == ProtocolNumbers.Udp &&
            oneWay &&
            flow.FwdPackets > _t.UdpFloodPackets &&
            flow.FwdPacketsPerSecond > _t.UdpFloodPacketsPerSecond;

        if (isUdpFlood)
            return Verdict(AttackTypes.DoS, "UDP flood");

        // ACK flood: many ACKs with no SYN and no payload-carrying handshake.
        bool isAckFlood =
            flow.AckCount > _t.AckFloodAcks &&
            flow.SynCount == 0 &&
            flow.FwdPackets > flow.BwdPackets * 2;

        if (isAckFlood)
            return Verdict(AttackTypes.DoS, "TCP ACK flood");

        // ICMP flood: elevated one-way ICMP packet rate. ICMP has no ports, so thresholds
        // are lower than the TCP/UDP floods.
        bool isIcmpFlood =
            flow.Protocol == ProtocolNumbers.Icmp &&
            flow.FwdPackets > _t.IcmpFloodPackets &&
            flow.FwdPacketsPerSecond > _t.IcmpFloodPacketsPerSecond;

        if (isIcmpFlood)
            return Verdict(AttackTypes.DoS, "ICMP flood");

        // ICMP ping flood: many echo requests with a matching reply stream.
        bool isIcmpPingFlood =
            flow.Protocol == ProtocolNumbers.Icmp &&
            flow.FwdPackets > _t.IcmpPingFloodPackets &&
            flow.BwdPackets > 0 &&
            flow.FwdPacketsPerSecond > _t.IcmpPingFloodPacketsPerSecond &&
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

        // SYN scan: SYNs answered with RSTs, little or no reply traffic.
        bool isSynScan =
            flow.SynCount > _t.ScanSyns &&
            flow.RstCount > flow.SynCount * 0.5 &&
            shortLived &&
            mostlyOutbound;

        if (isSynScan)
            return Verdict(AttackTypes.PortScan, "TCP SYN port scan");

        // Connect scan: full handshakes (SYN+ACK) that are reset immediately.
        bool isConnectScan =
            flow.SynCount > _t.ScanSyns &&
            flow.AckCount > flow.SynCount &&
            flow.RstCount > 0 &&
            shortLived &&
            mostlyOutbound;

        if (isConnectScan)
            return Verdict(AttackTypes.PortScan, "TCP connect port scan");

        // FIN/NULL/Xmas scan: no SYN at all, only FIN or RST probes.
        bool isFinNullXmasScan =
            flow.SynCount == 0 &&
            flow.AckCount == 0 &&
            (flow.FinCount > _t.FinRstScanPackets || flow.RstCount > _t.FinRstScanPackets) &&
            shortLived &&
            mostlyOutbound;

        if (isFinNullXmasScan)
            return Verdict(AttackTypes.PortScan, "FIN/NULL/Xmas port scan");

        // UDP scan: many small one-way probes to a single port with no replies. The
        // payload-size cap keeps payload-heavy one-way flows (media, bulk transfer) out
        // of this rule while still forwarding short small-probe bursts to the AI engine.
        bool isUdpScan =
            flow.Protocol == ProtocolNumbers.Udp &&
            flow.FwdPackets > _t.UdpScanPackets &&
            flow.FwdPackets <= 50 &&
            flow.BwdPackets == 0 &&
            flow.PacketSizeMean < _t.UdpScanMaxPayload &&
            shortLived;

        if (isUdpScan)
            return Verdict(AttackTypes.PortScan, "UDP port scan");

        // ICMP sweep: a run of one-way echo requests (replies suppressed). The floor above
        // a default `ping -c 4/5` stops a single blocked-host ping tripping it.
        bool isIcmpSweep =
            flow.Protocol == ProtocolNumbers.Icmp &&
            flow.FwdPackets > _t.IcmpSweepPackets &&
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
            flow.PacketSizeStdDev < _t.FlatTrafficStdDev &&
            flow.PacketSizeMean > 0;

        bool repeatedAttempts =
            flow.SynCount > _t.BruteForceSyns &&
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

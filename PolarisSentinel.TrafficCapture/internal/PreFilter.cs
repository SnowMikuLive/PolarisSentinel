using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.TrafficCapture.Internal;

// Rule-based pre-filter: detects known attack signatures, drops obvious noise, and forwards the rest to the AI engine.
internal sealed class PreFilter
{
    private readonly int _minPacketsForAnalysis;

    public PreFilter(int minPacketsForAnalysis)
    {
        _minPacketsForAnalysis = minPacketsForAnalysis;
    }

    // Classifies a finished flow into a known attack, a suspicious flow for the AI engine, or normal traffic.
    public PreFilterResult Classify(FlowRecord flow)
    {
        // Too few packets to compute meaningful statistics.
        if (flow.TotalPackets < _minPacketsForAnalysis)
            return PreFilterResult.Normal();

        // Short-lived flow, likely a handshake fragment.
        if (flow.DurationSeconds < 0.1)
            return PreFilterResult.Normal();

        // FlowKey orders endpoints by IP string, not by who sent first, so the
        // attacker may be on either side. Normalise so the dominant sender is forward.
        var direction = Normalise(flow);

        // Attack signatures run before the benign filters because floods are one-directional.
        var attack = DetectFlood(direction) ?? DetectScan(direction) ?? DetectBruteForce(direction);
        if (attack is not null)
            return attack;

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
    // assume forward = attacker regardless of how FlowKey ordered the endpoints.
    private static FlowRecord Normalise(FlowRecord flow)
    {
        if (flow.FwdPackets >= flow.BwdPackets)
        {
            return flow;
        }

        return new FlowRecord
        {
            StartTime = flow.StartTime,
            LastSeenTime = flow.LastSeenTime,
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
            PshCount = flow.PshCount
        };
    }

    // DoS family: SYN / UDP / ACK / ICMP floods, driven by flag counts and one-way packet volume.
    private PreFilterResult? DetectFlood(FlowRecord flow)
    {
        bool oneWay = flow.BwdPackets <= flow.FwdPackets * 0.1;

        // SYN flood: many SYNs, no handshake completion, no resets.
        bool isSynFlood =
            flow.SynCount > 10 &&
            flow.AckCount == 0 &&
            flow.RstCount == 0 &&
            flow.FwdPackets > flow.BwdPackets * 2;

        if (isSynFlood)
            return Verdict(AttackTypes.DoS, "TCP SYN flood");

        // UDP flood: high one-way UDP packet rate, no reply traffic.
        bool isUdpFlood =
            flow.Protocol == ProtocolNumbers.Udp &&
            oneWay &&
            flow.FwdPackets > 50 &&
            flow.FwdPacketsPerSecond > 100;

        if (isUdpFlood)
            return Verdict(AttackTypes.DoS, "UDP flood");

        // ACK flood: many ACKs with no SYN and no payload-carrying handshake.
        bool isAckFlood =
            flow.AckCount > 20 &&
            flow.SynCount == 0 &&
            flow.FwdPackets > flow.BwdPackets * 2;

        if (isAckFlood)
            return Verdict(AttackTypes.DoS, "TCP ACK flood");

        // ICMP flood: high one-way ICMP packet rate.
        bool isIcmpFlood =
            flow.Protocol == ProtocolNumbers.Icmp &&
            oneWay &&
            flow.FwdPackets > 50 &&
            flow.FwdPacketsPerSecond > 100;

        if (isIcmpFlood)
            return Verdict(AttackTypes.DoS, "ICMP flood");

        return null;
    }

    // Port scanning family: SYN / connect / FIN-NULL-Xmas / UDP scans and ICMP sweeps.
    private PreFilterResult? DetectScan(FlowRecord flow)
    {
        bool shortLived = flow.DurationSeconds < 2.0;
        bool mostlyOutbound = flow.BwdPackets <= flow.FwdPackets * 0.3;

        // SYN scan: SYNs answered with RSTs, little or no reply traffic.
        bool isSynScan =
            flow.SynCount > 3 &&
            flow.RstCount > flow.SynCount * 0.5 &&
            shortLived &&
            mostlyOutbound;

        if (isSynScan)
            return Verdict(AttackTypes.PortScan, "TCP SYN port scan");

        // Connect scan: full handshakes (SYN+ACK) that are reset immediately.
        bool isConnectScan =
            flow.SynCount > 3 &&
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
            (flow.FinCount > 3 || flow.RstCount > 3) &&
            shortLived &&
            mostlyOutbound;

        if (isFinNullXmasScan)
            return Verdict(AttackTypes.PortScan, "FIN/NULL/Xmas port scan");

        // UDP scan: many small one-way UDP packets to a single port, no replies.
        bool isUdpScan =
            flow.Protocol == ProtocolNumbers.Udp &&
            flow.FwdPackets > 5 &&
            flow.FwdPackets <= 50 &&
            flow.BwdPackets == 0 &&
            shortLived;

        if (isUdpScan)
            return Verdict(AttackTypes.PortScan, "UDP port scan");

        // ICMP sweep: several one-way echo requests probing hosts.
        bool isIcmpSweep =
            flow.Protocol == ProtocolNumbers.Icmp &&
            flow.FwdPackets > 3 &&
            flow.FwdPackets <= 50 &&
            flow.BwdPackets == 0 &&
            shortLived;

        if (isIcmpSweep)
            return Verdict(AttackTypes.PortScan, "ICMP sweep");

        return null;
    }

    // Brute force family: many short connections to SSH/FTP with flat, repeating packet sizes.
    private PreFilterResult? DetectBruteForce(FlowRecord flow)
    {
        bool isAuthPort = flow.DestinationPort == 22 || flow.DestinationPort == 21;
        if (!isAuthPort)
            return null;

        // Flat traffic: near-constant packet size and a steady connection cadence.
        bool flatTraffic =
            flow.PacketSizeStats.StdDev < 10 &&
            flow.PacketSizeStats.Mean > 0;

        bool repeatedAttempts =
            flow.SynCount > 3 &&
            flow.FwdPackets > 5 &&
            flow.PacketSizeStats.Mean < 200;

        if (!flatTraffic || !repeatedAttempts)
            return null;

        return flow.DestinationPort == 22
            ? Verdict(AttackTypes.BruteForce, "SSH brute force")
            : Verdict(AttackTypes.BruteForce, "FTP brute force");
    }

    private static PreFilterResult Verdict(string attackType, string description) =>
        PreFilterResult.KnownAttack(attackType, description);
}


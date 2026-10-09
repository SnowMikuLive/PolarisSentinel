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

    public PreFilterResult Classify(FlowStatistics flow)
    {
        var direction = Normalise(flow);

        var scan = DetectScan(direction);
        if (scan is not null)
            return scan;

        if (flow.TotalPackets < _t.MinPacketsForAnalysis)
            return PreFilterResult.Normal();

        var attack = DetectFlood(direction) ?? DetectBruteForce(direction);
        if (attack is not null)
            return attack;

        if (!IsRelevantToTrackedAttacks(direction))
            return PreFilterResult.Normal();

        return PreFilterResult.Suspicious("Flow relevant to a tracked attack; forwarded to the AI engine.");
    }

    private bool IsRelevantToTrackedAttacks(FlowStatistics flow)
    {
        if (flow.DestinationPort == 22 || flow.DestinationPort == 21)
            return true;

        if (flow.Protocol == ProtocolNumbers.Icmp)
            return true;

        bool oneWay = flow.BwdPackets <= flow.FwdPackets * 0.1;
        if (oneWay &&
            flow.FwdPackets >= _t.RelevanceMinPackets &&
            flow.PacketSizeMean < _t.UdpScanMaxPayload)
            return true;

        bool mostlyOneWay = flow.BwdPackets <= flow.FwdPackets * 0.3;
        if (mostlyOneWay &&
            (flow.SynCount >= _t.RelevanceMinSyns || flow.AckCount >= _t.RelevanceMinAcks))
            return true;

        bool shortLived = flow.DurationSeconds < 2.0;
        if (shortLived &&
            mostlyOneWay &&
            flow.FwdPackets >= _t.RelevanceMinPackets &&
            flow.PacketSizeMean < _t.UdpScanMaxPayload)
            return true;

        return false;
    }

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

    private PreFilterResult? DetectFlood(FlowStatistics flow)
    {
        bool oneWay = flow.BwdPackets <= flow.FwdPackets * 0.1;

        bool isSynFlood =
            flow.SynCount > _t.SynFloodSyns &&
            flow.AckCount == 0 &&
            flow.RstCount == 0 &&
            flow.FwdPackets > flow.BwdPackets * 2;

        if (isSynFlood)
            return Verdict(AttackTypes.DoS, "TCP SYN flood");

        bool isUdpFlood =
            flow.Protocol == ProtocolNumbers.Udp &&
            oneWay &&
            flow.FwdPackets > _t.UdpFloodPackets &&
            flow.FwdPacketsPerSecond > _t.UdpFloodPacketsPerSecond &&
            flow.PacketSizeMean < _t.UdpScanMaxPayload;

        if (isUdpFlood)
            return Verdict(AttackTypes.DoS, "UDP flood");

        bool isAckFlood =
            flow.AckCount > _t.AckFloodAcks &&
            flow.SynCount == 0 &&
            flow.FwdPackets > flow.BwdPackets * 2;

        if (isAckFlood)
            return Verdict(AttackTypes.DoS, "TCP ACK flood");

        bool isIcmpFlood =
            flow.Protocol == ProtocolNumbers.Icmp &&
            flow.FwdPackets > _t.IcmpFloodPackets &&
            flow.FwdPacketsPerSecond > _t.IcmpFloodPacketsPerSecond;

        if (isIcmpFlood)
            return Verdict(AttackTypes.DoS, "ICMP flood");

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

    private PreFilterResult? DetectScan(FlowStatistics flow)
    {
        bool shortLived = flow.DurationSeconds < 2.0;
        bool mostlyOutbound = flow.BwdPackets <= flow.FwdPackets * 0.3;

        bool isSynScan =
            flow.SynCount > _t.ScanSyns &&
            flow.RstCount > flow.SynCount * 0.5 &&
            shortLived &&
            mostlyOutbound;

        if (isSynScan)
            return Verdict(AttackTypes.PortScan, "TCP SYN port scan");

        bool isFilteredSynScan =
            flow.SynCount > _t.ScanSyns &&
            flow.BwdPackets == 0 &&
            shortLived &&
            mostlyOutbound;

        if (isFilteredSynScan)
            return Verdict(AttackTypes.PortScan, "TCP SYN scan (filtered)");

        bool isConnectScan =
            flow.SynCount > _t.ScanSyns &&
            flow.AckCount > flow.SynCount &&
            flow.RstCount > 0 &&
            shortLived &&
            mostlyOutbound;

        if (isConnectScan)
            return Verdict(AttackTypes.PortScan, "TCP connect port scan");

        bool isFinNullXmasScan =
            flow.SynCount == 0 &&
            flow.AckCount == 0 &&
            (flow.FinCount > _t.FinRstScanPackets || flow.RstCount > _t.FinRstScanPackets) &&
            shortLived &&
            mostlyOutbound;

        if (isFinNullXmasScan)
            return Verdict(AttackTypes.PortScan, "FIN/NULL/Xmas port scan");

        bool isUdpScan =
            flow.Protocol == ProtocolNumbers.Udp &&
            flow.FwdPackets > _t.UdpScanPackets &&
            flow.FwdPackets <= 50 &&
            flow.BwdPackets == 0 &&
            flow.PacketSizeMean < _t.UdpScanMaxPayload &&
            shortLived;

        if (isUdpScan)
            return Verdict(AttackTypes.PortScan, "UDP port scan");

        bool isIcmpSweep =
            flow.Protocol == ProtocolNumbers.Icmp &&
            flow.FwdPackets > _t.IcmpSweepPackets &&
            flow.FwdPackets <= 50 &&
            flow.BwdPackets <= 1 &&
            shortLived;

        if (isIcmpSweep)
            return Verdict(AttackTypes.PortScan, "ICMP sweep");

        bool isBareProbeBurst =
            mostlyOutbound &&
            flow.BwdPackets == 0 &&
            flow.FwdPackets >= _t.RelevanceMinPackets &&
            flow.PacketSizeMean < _t.UdpScanMaxPayload &&
            shortLived;

        if (isBareProbeBurst)
            return Verdict(AttackTypes.PortScan, "Port probe burst (no replies)");

        return null;
    }

    private PreFilterResult? DetectBruteForce(FlowStatistics flow)
    {
        bool isAuthPort = flow.DestinationPort == 22 || flow.DestinationPort == 21;
        if (!isAuthPort)
            return null;

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

    private static PreFilterResult Verdict(string attackType, string description) =>
        PreFilterResult.Suspicious($"{attackType}: {description}");
}

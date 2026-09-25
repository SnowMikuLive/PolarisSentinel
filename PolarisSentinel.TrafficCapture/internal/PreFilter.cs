using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.TrafficCapture.Internal;

// Rule-based pre-filter: detects attack signatures and forwards other flows to AI.
internal sealed class PreFilter
{
    private readonly int _minPacketsForAnalysis;

    public PreFilter(int minPacketsForAnalysis)
    {
        _minPacketsForAnalysis = minPacketsForAnalysis;
    }

    // 规则只确认攻击，未命中的非空流交给 AI。
    // Rules confirm attacks; other nonempty flows go to AI.
    public PreFilterResult? Classify(FlowRecord flow, out bool suspicious)
    {
        suspicious = false;
        if (flow.TotalPackets == 0)
            return null;

        if (flow.TotalPackets >= _minPacketsForAnalysis)
        {
            var attack = DetectFlood(flow) ?? DetectScan(flow) ?? DetectBruteForce(flow);
            if (attack is not null)
                return attack;
        }

        suspicious = true;
        return null;
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
            return Verdict(AttackTypes.DoS, "prefilter_syn_flood");

        // UDP flood: high one-way UDP packet rate, no reply traffic.
        bool isUdpFlood =
            flow.Protocol == ProtocolNumbers.Udp &&
            oneWay &&
            flow.FwdPackets > 50 &&
            flow.FwdPacketsPerSecond > 100;

        if (isUdpFlood)
            return Verdict(AttackTypes.DoS, "prefilter_udp_flood");

        // ACK flood: many ACKs with no SYN and no payload-carrying handshake.
        bool isAckFlood =
            flow.AckCount > 20 &&
            flow.SynCount == 0 &&
            flow.FwdPackets > flow.BwdPackets * 2;

        if (isAckFlood)
            return Verdict(AttackTypes.DoS, "prefilter_ack_flood");

        // ICMP flood: high one-way ICMP packet rate.
        bool isIcmpFlood =
            flow.Protocol == ProtocolNumbers.Icmp &&
            oneWay &&
            flow.FwdPackets > 50 &&
            flow.FwdPacketsPerSecond > 100;

        if (isIcmpFlood)
            return Verdict(AttackTypes.DoS, "prefilter_icmp_flood");

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
            return Verdict(AttackTypes.PortScan, "prefilter_syn_scan");

        // Connect scan: full handshakes (SYN+ACK) that are reset immediately.
        bool isConnectScan =
            flow.SynCount > 3 &&
            flow.AckCount > flow.SynCount &&
            flow.RstCount > 0 &&
            shortLived &&
            mostlyOutbound;

        if (isConnectScan)
            return Verdict(AttackTypes.PortScan, "prefilter_connect_scan");

        // FIN/NULL/Xmas scan: no SYN at all, only FIN or RST probes.
        bool isFinNullXmasScan =
            flow.SynCount == 0 &&
            flow.AckCount == 0 &&
            (flow.FinCount > 3 || flow.RstCount > 3) &&
            shortLived &&
            mostlyOutbound;

        if (isFinNullXmasScan)
            return Verdict(AttackTypes.PortScan, "prefilter_fin_null_xmas_scan");

        // UDP scan: many small one-way UDP packets to a single port, no replies.
        bool isUdpScan =
            flow.Protocol == ProtocolNumbers.Udp &&
            flow.FwdPackets > 5 &&
            flow.FwdPackets <= 50 &&
            flow.BwdPackets == 0 &&
            shortLived;

        if (isUdpScan)
            return Verdict(AttackTypes.PortScan, "prefilter_udp_scan");

        // ICMP sweep: several one-way echo requests probing hosts.
        bool isIcmpSweep =
            flow.Protocol == ProtocolNumbers.Icmp &&
            flow.FwdPackets > 3 &&
            flow.FwdPackets <= 50 &&
            flow.BwdPackets == 0 &&
            shortLived;

        if (isIcmpSweep)
            return Verdict(AttackTypes.PortScan, "prefilter_icmp_sweep");

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
            ? Verdict(AttackTypes.BruteForce, "prefilter_ssh_brute_force")
            : Verdict(AttackTypes.BruteForce, "prefilter_ftp_brute_force");
    }

    private static PreFilterResult Verdict(string attackType, string reason) =>
        new() { AttackType = attackType, Confidence = 1f, Reason = reason };
}


namespace PolarisSentinel.TrafficCapture.Internal;

internal sealed class PreFilter
{
    private readonly int _minPacketsForAnalysis;

    public PreFilter(int minPacketsForAnalysis)
    {
        _minPacketsForAnalysis = minPacketsForAnalysis;
    }

    public bool IsWorthDeepAnalysis(FlowRecord flow)
    {
        // Rule 1: Too few packets to compute meaningful statistics
        if (flow.TotalPackets < _minPacketsForAnalysis)
            return false;

        // Rule 2: Duration too short (< 0.1s) - likely handshake or connection fragment
        if (flow.DurationSeconds < 0.1)
            return false;

        // Rule 3: Unidirectional traffic (broadcast/multicast)
        if (flow.FwdPackets == 0 || flow.BwdPackets == 0)
            return false;
        
        // Rule 4: Suspicious patterns - SYN flood detection
        bool isSynFlood =
            flow.SynCount > 10 &&
            flow.AckCount == 0 &&
            flow.RstCount == 0 &&
            flow.FwdPackets > flow.BwdPackets * 2;

        if (isSynFlood)
            return true;  // Definitely suspicious
        
        // Rule 5: Port scanning pattern
        bool isPortScan =
            flow.SynCount > 0 &&
            flow.RstCount > flow.SynCount * 0.5 &&
            flow.DurationSeconds < 2.0 &&
            flow.FwdPackets > 5 &&
            flow.BwdPackets <= flow.FwdPackets * 0.3;

        if (isPortScan)
            return true;  // Definitely suspicious

        // Rule 6: Normal HTTPS/HTTP traffic with balanced flows
        bool isNormalWebTraffic =
            (flow.DestinationPort == 443 || flow.DestinationPort == 80) &&
            flow.FwdPackets > 5 &&
            flow.BwdPackets > 5 &&
            flow.SynCount <= 1 &&
            flow.RstCount == 0 &&
            flow.FinCount <= 2 &&
            flow.DownUpRatio > 0.1 &&
            flow.DownUpRatio < 10;

        if (isNormalWebTraffic)
            return false;

        // Rule 7: Normal two-way conversation with clean handshake
        bool isOrdinaryTwoWayTraffic =
            flow.FwdPackets > 0 &&
            flow.BwdPackets > 0 &&
            flow.DurationSeconds > 1.0 &&
            flow.SynCount <= 1;

        if (isOrdinaryTwoWayTraffic)
            return false;

        // Rule 8: Suspicious flag combinations
        bool hasSuspiciousFlags =
            flow.RstCount > 5 ||  // Too many resets
            flow.SynCount > 5 ||  // Too many SYN without proper handshake
            (flow.SynCount == 0 && flow.FwdPackets > 10) ||  // No SYN in TCP traffic
            (flow.FinCount > 10);  // Too many FINs

        if (hasSuspiciousFlags)
            return true;

        // Anything else - susipicious enough to sending to AI engine
        return true;
    }
}
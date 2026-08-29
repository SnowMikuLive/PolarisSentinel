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

        // Rule 4: Normal HTTPS/HTTP traffic with balanced flows
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

        // Rule 5: Normal two-way conversation with clean handshake
        bool isOrdinaryTwoWayTraffic =
            flow.FwdPackets > 0 &&
            flow.BwdPackets > 0 &&
            flow.DurationSeconds > 1.0 &&
            flow.SynCount <= 1;

        if (isOrdinaryTwoWayTraffic)
            return false;

        // Anything else - susipicious enough to sending to AI engine
        return true;
    }
}
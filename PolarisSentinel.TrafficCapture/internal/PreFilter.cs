namespace PolarisSentinel.Capture.Internal;

internal sealed class PreFilter
{
    private readonly int _minPacketsForAnalysis;

    public PreFilter(int minPacketsForAnalysis)
    {
        _minPacketsForAnalysis = minPacketsForAnalysis;
    }

    public bool IsWorthDeepAnalysis(FlowRecord flow)
    {
        // Rule 1: too few packets to compute meaningful statistics
        if (flow.TotalPackets < _minPacketsForAnalysis)
            return false;

        // Rule 2: a normal, completed, two-way conversation with a clean handshake 
        bool isOrdinaryTwoWayTraffic =
            flow.FwdPackets > 0 &&
            flow.BwdPackets > 0 &&
            flow.DurationSeconds > 1.0 &&
            flow.SynCount <= 1;

        if (isOrdinaryTwoWayTraffic)
            return false;

        // Anything else
        return true;
    }
}

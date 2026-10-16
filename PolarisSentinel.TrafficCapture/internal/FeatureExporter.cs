using PolarisSentinel.Core.Models;

namespace PolarisSentinel.TrafficCapture.Internal;

internal static class FeatureExporter
{
    public static readonly string[] FeatureNames = FlowSnapshot.FeatureNames;

    public static FlowFeatureVector Export(
        FlowRecord flow,
        FlowKey key,
        string sourceIp,
        ushort sourcePort,
        string destinationIp,
        ushort destinationPort,
        byte protocol,
        PreFilterResult? preFilterVerdict = null,
        bool isInbound = false)
    {
        float durationMs = Clamp(flow.DurationSeconds * 1000);

        float bytesPerMs = durationMs > 0
           ? Clamp(flow.TotalBytes / (double)durationMs)
           : 0;

        float pktsPerMs = durationMs > 0
            ? Clamp(flow.TotalPackets / (double)durationMs)
            : 0;

        float downUpRatio = flow.FwdPackets > 0
            ? Clamp((double)flow.BwdPackets / flow.FwdPackets)
            : 0;

        float[] features =
        {
            durationMs,
            Clamp(flow.FwdPackets),
            Clamp(flow.BwdPackets),
            Clamp(flow.FwdBytes),
            Clamp(flow.BwdBytes),
            Clamp(flow.PacketSizeStats.Min),
            Clamp(flow.PacketSizeStats.Max),
            Clamp(flow.PacketSizeStats.Mean),
            Clamp(flow.PacketSizeStats.StdDev),
            Clamp(flow.FwdIatStats.Mean),
            Clamp(flow.FwdIatStats.StdDev),
            Clamp(flow.FwdIatStats.Max),
            Clamp(flow.FwdIatStats.Min),
            Clamp(flow.BwdIatStats.Mean),
            Clamp(flow.BwdIatStats.StdDev),
            Clamp(flow.BwdIatStats.Max),
            Clamp(flow.BwdIatStats.Min),
            bytesPerMs,
            pktsPerMs,
            downUpRatio
        };

        return new FlowFeatureVector
        {
            Features = features,
            SourceIp = sourceIp,
            SourcePort = sourcePort,
            DestinationIp = destinationIp,
            DestinationPort = destinationPort,
            Protocol = protocol,
            FlowStartTime = flow.StartTime,
            FlowEndTime = flow.LastSeenTime,
            SynCount = flow.SynCount,
            AckCount = flow.AckCount,
            FinCount = flow.FinCount,
            RstCount = flow.RstCount,
            PshCount = flow.PshCount,
            PreFilterVerdict = preFilterVerdict,
            IsInbound = isInbound
        };
    }

    private static float Clamp(double value) =>
        double.IsFinite(value) && value > 0 ? (float)value : 0f;
}

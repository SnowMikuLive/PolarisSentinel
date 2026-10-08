using PolarisSentinel.Core.Models;

namespace PolarisSentinel.TrafficCapture.Internal;

internal static class FeatureExporter
{
    // The feature schema has one source of truth in Core, so the capture layer, the alert
    // snapshot and the models cannot drift apart.
    public static readonly string[] FeatureNames = FlowSnapshot.FeatureNames;

    public static FlowFeatureVector Export(FlowRecord flow, FlowKey key, string sourceIp, ushort sourcePort, string destinationIp, ushort destinationPort, byte protocol)
    {
        float durationMs = (float)(flow.DurationSeconds * 1000);

        float bytesPerMs = durationMs > 0
           ? (float)(flow.TotalBytes / durationMs)
           : 0;

        float pktsPerMs = durationMs > 0
            ? (float)(flow.TotalPackets / durationMs)
            : 0;

        // Matches the training script: down_up_ratio = bwd_pkts / fwd_pkts
        float downUpRatio = flow.FwdPackets > 0
            ? (float)((double)flow.BwdPackets / flow.FwdPackets)
            : 0;

        float[] features =
        {
            durationMs,
            flow.FwdPackets,
            flow.BwdPackets,
            flow.FwdBytes,
            flow.BwdBytes,
            (float)flow.PacketSizeStats.Min,
            (float)flow.PacketSizeStats.Max,
            (float)flow.PacketSizeStats.Mean,
            (float)flow.PacketSizeStats.StdDev,
            (float)flow.FwdIatStats.Mean,
            (float)flow.FwdIatStats.StdDev,
            (float)flow.FwdIatStats.Max,
            (float)flow.FwdIatStats.Min,
            (float)flow.BwdIatStats.Mean,
            (float)flow.BwdIatStats.StdDev,
            (float)flow.BwdIatStats.Max,
            (float)flow.BwdIatStats.Min,
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
            TotalPackets = flow.TotalPackets,
            TotalBytes = flow.TotalBytes,
            SynCount = flow.SynCount,
            AckCount = flow.AckCount,
            FinCount = flow.FinCount,
            RstCount = flow.RstCount,
            PshCount = flow.PshCount
        };
    }
}

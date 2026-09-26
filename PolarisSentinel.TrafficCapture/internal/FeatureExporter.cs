using PolarisSentinel.Core.Models;
using System.Diagnostics;

namespace PolarisSentinel.TrafficCapture.Internal;

internal static class FeatureExporter
{
    //Human readable list of each index in Features means
   
    public static readonly string[] FeatureNames =
    {
        "flow_duration_ms",
        "total_fwd_packets",
        "total_bwd_packets",
        "total_fwd_bytes",
        "total_bwd_bytes",
        "pkt_len_min",
        "pkt_len_max",
        "pkt_len_mean",
        "pkt_len_std",
        "fwd_iat_mean_ms",
        "fwd_iat_std_ms",
        "fwd_iat_max_ms",
        "fwd_iat_min_ms",
        "bwd_iat_mean_ms",
        "bwd_iat_std_ms",
        "bwd_iat_max_ms",
        "bwd_iat_min_ms",
        "flow_bytes_per_ms",
        "flow_pkts_per_ms",
        "down_up_ratio"
            
    };

    public static FlowFeatureVector Export(FlowRecord flow, FlowKey key, string sourceIp, ushort sourcePort, string destinationIp, ushort destinationPort, byte protocol)
    {
        float durationMs = (float)(flow.DurationSeconds * 1000);

        float bytesPerMs = durationMs > 0
           ? (float)(flow.TotalBytes / durationMs)
           : 0;

        float pktsPerMs = durationMs > 0
            ? (float)(flow.TotalPackets / durationMs)
            : 0;

        //与训练脚本一致：down_up_ratio =下行包数/上行包数
        //Matches the training script:down_up_ratio = bwd_pkts / fwd_pkts
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

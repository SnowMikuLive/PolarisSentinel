namespace PolarisSentinel.Core.Models;


public class FlowFeatureVector
{
    public required float[] Features { get; init; }

    public required string SourceIp { get; init; }
    public required ushort SourcePort { get; init; }
    public required string DestinationIp { get; init; }
    public required ushort DestinationPort { get; init; }
    public required byte Protocol { get; init; }

    public required DateTime FlowStartTime { get; init; }
    public required DateTime FlowEndTime { get; init; }

    public long TotalPackets { get; init; }
    public long TotalBytes { get; init; }

    // Rule-based verdict from the capture-layer pre-filter; null when the flow is only suspicious.
    public PreFilterResult? PreFilterVerdict { get; init; }
}

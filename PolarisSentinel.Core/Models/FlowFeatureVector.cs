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

    // TCP flag counters, carried through for alert detail and policy decisions.
    public int SynCount { get; init; }
    public int AckCount { get; init; }
    public int FinCount { get; init; }
    public int RstCount { get; init; }
    public int PshCount { get; init; }

    // Rule-based verdict from the capture-layer pre-filter.
    public PreFilterResult? PreFilterVerdict { get; init; }

    // True when the flow arrived at this host (remote -> local). Only inbound flows are
    // treated as attacks; outbound flows are captured and shown but never blocked.
    public bool IsInbound { get; init; }
}

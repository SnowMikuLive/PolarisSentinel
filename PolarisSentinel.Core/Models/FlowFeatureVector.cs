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

    public int SynCount { get; init; }
    public int AckCount { get; init; }
    public int FinCount { get; init; }
    public int RstCount { get; init; }
    public int PshCount { get; init; }

    public PreFilterResult? PreFilterVerdict { get; init; }

    public bool IsInbound { get; init; }
}

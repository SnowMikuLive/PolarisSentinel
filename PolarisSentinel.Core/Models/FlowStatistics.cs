namespace PolarisSentinel.Core.Models;

// Raw per-flow statistics the rule-based pre-filter classifies. This is the domain
// view of a flow: it carries no capture-library types, so the detection heuristics
// can live in the domain layer while the capture adapter only produces these numbers.
public class FlowStatistics
{
    public byte Protocol { get; init; }

    public int DestinationPort { get; init; }

    public long FwdPackets { get; init; }

    public long BwdPackets { get; init; }

    public long FwdBytes { get; init; }

    public long BwdBytes { get; init; }

    public int SynCount { get; init; }

    public int AckCount { get; init; }

    public int FinCount { get; init; }

    public int RstCount { get; init; }

    public int PshCount { get; init; }

    public double DurationSeconds { get; init; }

    // Mean and standard deviation of the packet sizes in the flow.
    public double PacketSizeMean { get; init; }

    public double PacketSizeStdDev { get; init; }

    public long TotalPackets => FwdPackets + BwdPackets;

    public double FwdPacketsPerSecond =>
        DurationSeconds > 0 ? FwdPackets / DurationSeconds : FwdPackets;

    public double DownUpRatio => BwdBytes > 0
        ? (double)FwdBytes / BwdBytes
        : (FwdBytes > 0 ? double.MaxValue : 1.0);
}

namespace PolarisSentinel.Core.Models;

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

    public double PacketSizeMean { get; init; }

    public double PacketSizeStdDev { get; init; }

    public long TotalPackets => FwdPackets + BwdPackets;

    public double FwdPacketsPerSecond =>
        DurationSeconds > 0 ? FwdPackets / DurationSeconds : FwdPackets;
}

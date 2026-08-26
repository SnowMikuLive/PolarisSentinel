namespace PolarisSentinel.Capture.Internal;

internal sealed class FlowRecord
{
    public required DateTime StartTime { get; init; }
    public DateTime LastSeenTime { get; set; }

    public long FwdPackets { get; set; }
    public long BwdPackets { get; set; }
    public long FwdBytes { get; set; }
    public long BwdBytes { get; set; }

    public RunningStats PacketSizeStats { get; } = new();
    public RunningStats FwdIatStats { get; } = new();
    public RunningStats BwdIatStats { get; } = new();

    public DateTime? LastFwdPacketTime { get; set; }
    public DateTime? LastBwdPacketTime { get; set; }

    public int SynCount { get; set; }
    public int AckCount { get; set; }
    public int FinCount { get; set; }
    public int RstCount { get; set; }
    public int PshCount { get; set; }

    public double DurationSeconds => (LastSeenTime - StartTime).TotalSeconds;
    public long TotalPackets => FwdPackets + BwdPackets;
}

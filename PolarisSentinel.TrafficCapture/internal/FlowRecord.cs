namespace PolarisSentinel.TrafficCapture.Internal;

//For store flow records
internal sealed class FlowRecord
{
    public required DateTime StartTime { get; init; }
    public DateTime LastSeenTime { get; set; }

    public long FwdPackets { get; set; }
    public long BwdPackets { get; set; }
    public long FwdBytes { get; set; }
    public long BwdBytes { get; set; }
    public long TotalBytes => FwdBytes + BwdBytes;

    public double FwdIatMin => FwdIatStats.Min;
    public double FwdIatMax => FwdIatStats.Max;
    public double BwdIatMin => BwdIatStats.Min;
    public double BwdIatMax => BwdIatStats.Max;

    public double PktLenMin => PacketSizeStats.Min;
    public double PktLenMax => PacketSizeStats.Max;

    public RunningStats PacketSizeStats { get; } = new();
    public RunningStats FwdIatStats { get; } = new();
    public RunningStats BwdIatStats { get; } = new();

    public DateTime? LastFwdPacketTime { get; set; }
    public DateTime? LastBwdPacketTime { get; set; }
    //For the prefilter to trigae benign
    public int SynCount { get; set; }
    public int AckCount { get; set; }
    public int FinCount { get; set; }
    public int RstCount { get; set; }
    public int PshCount { get; set; }

    public double DownUpRatio => BwdBytes > 0 ? (double)FwdBytes / BwdBytes : (FwdBytes > 0 ? double.MaxValue : 1.0);
    public double DurationSeconds => (LastSeenTime - StartTime).TotalSeconds;
    public long TotalPackets => FwdPackets + BwdPackets;

    // Outbound packet rate, used by the pre-filter to spot floods.
    public double FwdPacketsPerSecond => DurationSeconds > 0 ? FwdPackets / DurationSeconds : 0;

    public int DestinationPort { get; internal set; }

    // IP protocol number; set when the flow is created.
    public byte Protocol { get; internal set; }
}

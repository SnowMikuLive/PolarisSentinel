namespace PolarisSentinel.TrafficCapture.Internal;

internal sealed class FlowRecord
{
    public required DateTime StartTime { get; init; }
    public DateTime LastSeenTime { get; set; }
    public string SourceIp { get; init; } = string.Empty;
    public ushort SourcePort { get; init; }
    public string DestinationIp { get; init; } = string.Empty;

    public long FwdPackets { get; set; }
    public long BwdPackets { get; set; }
    public long FwdBytes { get; set; }
    public long BwdBytes { get; set; }
    public long TotalBytes => FwdBytes + BwdBytes;

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

    public int DestinationPort { get; internal set; }

    public byte Protocol { get; internal set; }

    public bool IsInbound { get; internal set; }
}

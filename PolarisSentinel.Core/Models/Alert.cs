using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// A detection result: what was seen, where, and how it was classified.
// Policy decisions are not stored here; they live on the Rule the decision produced.
public class Alert
{
    public string Id { get; set; } = string.Empty;

    public DetectionSource DetectionSource { get; set; }

    public required string AttackType { get; set; }

    public float? ConfidenceScore { get; set; }

    public bool SpoofedSource { get; set; }

    public string? Description { get; set; }

    public required string SourceIp { get; set; }

    public int SourcePort { get; set; }

    public required string DestinationIp { get; set; }

    public int DestinationPort { get; set; }

    public byte Protocol { get; set; }

    public int SynCount { get; set; }

    public int AckCount { get; set; }

    public int FinCount { get; set; }

    public int RstCount { get; set; }

    public int PshCount { get; set; }

    public string? FlowSnapshotJson { get; set; }

    public string? BehaviorSnapshotJson { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.Now;
}

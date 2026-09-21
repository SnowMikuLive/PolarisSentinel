using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// Stores an AI inference result with the 5-tuple that produced it.
// Also serves as the inference engine output (merged from DetectionResult).
public class Alert
{
    // Human-readable id, e.g. "A-RF-1" / "A-IF-2".
    public string Id { get; set; } = string.Empty;

    // 5-tuple
    public required string SourceIp { get; set; }

    public int SourcePort { get; set; }

    public required string DestinationIp { get; set; }

    public int DestinationPort { get; set; }

    public byte Protocol { get; set; }

    // Inference result
    public required string AttackType { get; set; }

    public float Confidence { get; set; }

    public Severity? Severity { get; set; }

    public DetectionSource Source { get; set; }

    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;

    // Policy decision applied to this alert
    //该告警对应的策略决策
    public PolicyAction Action { get; set; } = PolicyAction.Monitor;

    public string? RuleName { get; set; }

    public required string Reason { get; set; }
}

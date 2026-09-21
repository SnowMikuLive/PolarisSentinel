using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// The 5-tuple plus detection outcome produced by the capture layer or the AI engine,
// and enriched by the policy engine with the action it decided on.
public class Alert
{
    // Human-readable id, e.g. "A-RF-1" / "A-IF-2" / "A-PF-3".
    public string Id { get; set; } = string.Empty;

    // 5-tuple
    public required string SourceIp { get; set; }

    public int SourcePort { get; set; }

    public required string DestinationIp { get; set; }

    public int DestinationPort { get; set; }

    public byte Protocol { get; set; }

    // Detection outcome
    public required string AttackType { get; set; }

    public float Confidence { get; set; }

    public DetectionSource Source { get; set; }

    public DateTime DetectedAt { get; set; } = DateTime.Now;

    // Policy decision applied to this alert.
    public PolicyAction Action { get; set; } = PolicyAction.Monitor;

    public string? RuleName { get; set; }

    public required string Reason { get; set; }

    public DateTime DecidedAt { get; set; } = DateTime.Now;
}

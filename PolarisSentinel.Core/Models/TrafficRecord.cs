namespace PolarisSentinel.Core.Models;

public class TrafficRecord
{
    public long Id { get; set; }

    public string AlertId { get; set; } = string.Empty;

    public string SourceIp { get; set; } = string.Empty;

    public int SourcePort { get; set; }

    public string DestinationIp { get; set; } = string.Empty;

    public int DestinationPort { get; set; }

    public string AttackType { get; set; } = string.Empty;

    public float? ConfidenceScore { get; set; }

    public string Action { get; set; } = string.Empty;

    public string Reason { get; set; } = string.Empty;

    public string DecisionReason { get; set; } = string.Empty;

    public string DecisionText { get; set; } = string.Empty;

    public string Source { get; set; } = string.Empty;

    public string? RuleName { get; set; }

    public string Verdict { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.Now;
}

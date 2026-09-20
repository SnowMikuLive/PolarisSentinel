using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// A policy owned by a user (ASP.NET Identity IdentityUser). Defines how detections are handled.
// Also carries the decision produced when a detection is evaluated (merged from PolicyDecision).
public class Policy
{
    // Human-readable id, e.g. "P-1".
    public string Id { get; set; } = string.Empty;

    public required string Name { get; set; }

    // Optional free-text description.
    public string? Description { get; set; }

    public string UserId { get; set; } = string.Empty;

    // Which model this policy applies to (RandomForest / IsolationForest).
    public DetectionSource DetectionSource { get; set; } = DetectionSource.RandomForest;

    public PolicyAction Action { get; set; } = PolicyAction.Ignore;

    public float RfConfidenceThreshold { get; set; } = 0.6f;

    public float AutoBlockConfidenceThreshold { get; set; } = 0.8f;

    public int BlockDurationMinutes { get; set; } = 60;

    public int DecisionCooldownSeconds { get; set; } = 60;

    public bool IsActive { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // ---- Settings fields (merged from PolicySettings) ----

    // IF default threshold; inference reads ONNX.
    public double IfAnomalyThreshold { get; set; } = -0.150806;

    public int FlowIdleTimeoutMilliseconds { get; set; } = 120000;

    public int PreFilterMinPackets { get; set; } = 3;

    // Block downgraded to Monitor on match.
    public string[] Allowlist { get; set; } = [];

    // ---- Decision fields (merged from PolicyDecision) ----

    // Alert produced by this decision.
    public string AlertId { get; set; } = string.Empty;

    public string SourceIp { get; set; } = string.Empty;

    public string AttackType { get; set; } = string.Empty;

    public float Confidence { get; set; }

    public DateTime DecidedAt { get; set; } = DateTime.UtcNow;

    // Reason code.
    public string Reason { get; set; } = string.Empty;

    // Firewall rule name populated when a Block reuses an existing rule.
    public string? RuleName { get; set; }
}

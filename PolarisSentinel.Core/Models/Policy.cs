using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// A matching rule: when an alert satisfies its conditions, the policy's action is applied.
public class Policy
{
    public string Id { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    public string? Description { get; set; }

    // Condition: which detector produced the alert. Null means any source.
    public DetectionSource? DetectionSource { get; set; }

    // Condition: minimum Random Forest confidence. Null means the RF threshold is not checked.
    public float? RfThreshold { get; set; }

    // Condition: minimum Isolation Forest confidence. Null means the IF threshold is not checked.
    public float? IfThreshold { get; set; }

    // Condition: attack category to match. Null means any attack type.
    public string? AttackType { get; set; }

    // Action applied to a matching alert.
    public PolicyAction Action { get; set; } = PolicyAction.Monitor;

    public int BlockDurationMinutes { get; set; } = 60;

    // 0..100 where 100 is the highest priority.
    public int Priority { get; set; }

    public bool IsEnabled { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.Now;

    public DateTime UpdatedAt { get; set; } = DateTime.Now;

    // True when the alert satisfies every condition this policy declares.
    // Domain logic: both the policy engine and the detection pipeline gate on this.
    public bool Matches(Alert alert)
    {
        if (DetectionSource is { } source && source != alert.DetectionSource)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(AttackType) &&
            !string.Equals(AttackType, alert.AttackType, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return MeetsThreshold(alert);
    }

    // The threshold that applies is the one belonging to the detector that produced the alert.
    // A heuristic alert carries no model score, so it always passes.
    public bool MeetsThreshold(Alert alert)
    {
        if (alert.DetectionSource == Enums.DetectionSource.HeuristicBased)
        {
            return true;
        }

        float? threshold = ThresholdFor(alert.DetectionSource);
        return threshold is null || alert.ConfidenceScore is { } score && score >= threshold;
    }

    // The confidence threshold this policy applies to a given detection source,
    // or null when the source is not threshold-gated.
    public float? ThresholdFor(Enums.DetectionSource source) => source switch
    {
        Enums.DetectionSource.RandomForest => RfThreshold,
        Enums.DetectionSource.IsolationForest => IfThreshold,
        _ => null
    };
}

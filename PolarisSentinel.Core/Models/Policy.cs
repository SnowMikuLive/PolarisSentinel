using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// A matching rule: when an alert satisfies its conditions, the policy's action is applied.
public class Policy
{
    public string Id { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    public string? Description { get; set; }

    public DetectionSource? DetectionSource { get; set; }

    public float? RfThreshold { get; set; }

    public float? IfThreshold { get; set; }

    public string? AttackType { get; set; }

    public PolicyAction Action { get; set; } = PolicyAction.Monitor;

    public int BlockDurationMinutes { get; set; } = 60;

    public int Priority { get; set; }

    public bool IsEnabled { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.Now;

    public DateTime UpdatedAt { get; set; } = DateTime.Now;

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

    public bool MeetsThreshold(Alert alert)
    {
        if (alert.DetectionSource == Enums.DetectionSource.HeuristicBased)
        {
            return true;
        }

        float? threshold = ThresholdFor(alert.DetectionSource);
        return threshold is null || alert.ConfidenceScore is { } score && score >= threshold;
    }

    public float? ThresholdFor(Enums.DetectionSource source) => source switch
    {
        Enums.DetectionSource.RandomForest => RfThreshold,
        Enums.DetectionSource.IsolationForest => IfThreshold,
        _ => null
    };
}

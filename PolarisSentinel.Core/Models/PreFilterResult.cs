namespace PolarisSentinel.Core.Models;

// Rule-based verdict produced by the capture-layer pre-filter.
public class PreFilterResult
{
    public required string AttackType { get; init; }

    // Confidence the rule assigns to its own verdict.
    public float Confidence { get; init; } = 1f;

    public required string Reason { get; init; }
}

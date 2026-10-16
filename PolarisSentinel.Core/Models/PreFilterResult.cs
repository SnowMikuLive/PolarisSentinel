namespace PolarisSentinel.Core.Models;

public class PreFilterResult
{
    public bool IsKnownAttack { get; init; }

    public bool IsSuspicious { get; init; }

    public string? AttackType { get; init; }

    public string? Description { get; init; }

    public bool IsSpoofedSource { get; init; }

    public BehaviorWindowStats? Aggregate { get; init; }

    public static PreFilterResult Normal() => new();

    public static PreFilterResult Suspicious(string description, BehaviorWindowStats? aggregate = null) =>
        new() { IsSuspicious = true, Description = description, Aggregate = aggregate };

    public static PreFilterResult KnownAttack(string attackType, string description, BehaviorWindowStats? aggregate = null) =>
        new() { IsKnownAttack = true, IsSuspicious = true, AttackType = attackType, Description = description, Aggregate = aggregate };

    public static PreFilterResult SpoofedFlood(string attackType, string description, BehaviorWindowStats? aggregate = null) =>
        new() { IsKnownAttack = true, IsSuspicious = true, AttackType = attackType, Description = description, IsSpoofedSource = true, Aggregate = aggregate };
}

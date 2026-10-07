namespace PolarisSentinel.Core.Models;

// Result of the rule-based pre-filter, the upstream stage of the AI engine.
public class PreFilterResult
{
    // The flow matched a known attack signature.
    public bool IsKnownAttack { get; init; }

    // The flow is not a known attack but is not clearly normal either, so it should reach the AI engine.
    public bool IsSuspicious { get; init; }

    // Attack category, set only when IsKnownAttack is true.
    public string? AttackType { get; init; }

    // Short human-readable explanation, e.g. "SYN flood".
    public string? Description { get; init; }

    // True when the source address cannot be trusted (spoofed/random-source flood). The
    // pipeline then targets the flooded destination instead of the source, since blocking
    // a random spoofed IP would be ineffective.
    public bool IsSpoofedSource { get; init; }

    public static PreFilterResult Normal() => new();

    public static PreFilterResult Suspicious(string description) =>
        new() { IsSuspicious = true, Description = description };

    public static PreFilterResult KnownAttack(string attackType, string description) =>
        new() { IsKnownAttack = true, IsSuspicious = true, AttackType = attackType, Description = description };

    // A flood whose source address is spoofed/random; the destination is the real target.
    public static PreFilterResult SpoofedFlood(string attackType, string description) =>
        new() { IsKnownAttack = true, IsSuspicious = true, AttackType = attackType, Description = description, IsSpoofedSource = true };
}

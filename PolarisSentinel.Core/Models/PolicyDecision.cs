using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

public class PolicyDecision
{
    public required Guid AlertId { get; init; } = Guid.NewGuid();

    public required PolicyAction Action { get; init; }

    public required string SourceIp { get; init; }

    public required string AttackType { get; init; }

    public required float Confidence { get; init; }

    public required DateTime DecidedAt { get; init; }
}

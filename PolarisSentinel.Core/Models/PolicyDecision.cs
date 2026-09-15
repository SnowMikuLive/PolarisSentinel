using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// 策略决策结果
// Policy decision for one detection
public class PolicyDecision
{
    public required Guid AlertId { get; init; } = Guid.NewGuid();

    public required PolicyAction Action { get; init; }

    public required string SourceIp { get; init; }

    public required string AttackType { get; init; }

    public required float Confidence { get; init; }

    public DetectionSource Source { get; init; }

    // 执行器中实际使用的规则名
    // Actual rule name used by the enforcer
    public string? RuleName { get; set; }

    public required DateTime DecidedAt { get; init; }

    // 原因码
    // Reason code
    public string Reason { get; init; } = string.Empty;
}

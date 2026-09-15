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

    // 检测来源（随机森林 / 孤立森林 / 无）
    // Detection source (RandomForest / IsolationForest / None)
    public required DetectionSource Source { get; init; }

    public required DateTime DecidedAt { get; init; } = DateTime.UtcNow;

    // 原因码
    // Reason code
    public string Reason { get; init; } = string.Empty;

    // 封禁时命中的防火墙规则名，复用已有规则时填充
    // Firewall rule name populated when a Block reuses an existing rule
    public string? RuleName { get; set; }
}

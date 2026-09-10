using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// 策略引擎对单次检测结果做出的处置决定，供下游防火墙执行器消费。
// Policy action for one detection result, consumed by the downstream firewall enforcer.
public class PolicyDecision
{
    // 本次决策的唯一标识，用于审计和去重
    // Unique identifier for auditing and deduplication
    public required Guid AlertId { get; init; } = Guid.NewGuid();

    public required PolicyAction Action { get; init; }

    public required string SourceIp { get; init; }

    public required string AttackType { get; init; }

    public required float Confidence { get; init; }

    public required DateTime DecidedAt { get; init; }

    // 机器可读的原因码，便于日志检索和 Dashboard 展示
    // Machine-readable reason code for log search and dashboard display
    public string Reason { get; init; } = string.Empty;
}

namespace PolarisSentinel.Core.Models;

// 对外展示的防火墙规则摘要
// Firewall rule summary exposed to callers
public class FirewallRuleInfo
{
    public required string Name { get; init; }
    public required string RemoteAddress { get; init; }
    public required bool Enabled { get; init; }
    public required bool IsBlockRule { get; init; }

    // 旧规则可能没有审计信息
    // Older rules may not contain audit details
    public Guid? AlertId { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }
    public string? AttackType { get; init; }
}

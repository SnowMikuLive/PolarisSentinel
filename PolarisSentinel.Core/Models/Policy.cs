using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

public class Policy
{
    public string Id { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    public DetectionSource DetectionSource { get; set; } = DetectionSource.RandomForest;

    public float? RfConfidenceThreshold { get; set; }


    public float? IfConfidenceThreshold { get; set; }

    public int BlockDurationMinutes { get; set; } = 60;

    public int DecisionCooldownSeconds { get; set; } = 60;

    public string Allowlist { get; set; } = string.Empty;

    public string? MatchAttackTypes { get; set; }

    // 0 = any protocol.
    public byte MatchProtocol { get; set; }

    public PolicyAction RuleSourceIpAction { get; set; } = PolicyAction.Block;

    public PolicyAction RuleSourcePortAction { get; set; } = PolicyAction.Block;


    public PolicyAction RuleDestinationIpAction { get; set; } = PolicyAction.Block;

    public PolicyAction RuleDestinationPortAction { get; set; } = PolicyAction.Block;


    public DateTime CreatedAt { get; set; } = DateTime.Now;

    public DateTime UpdatedAt { get; set; } = DateTime.Now;
}

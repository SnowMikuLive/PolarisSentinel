using PolarisSentinel.Core.Enums;
using System.ComponentModel.DataAnnotations;

namespace PolarisSentinel.Core.Models;

public class Policy
{
    public string Id { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;

    public DetectionSource DetectionSource { get; set; } = DetectionSource.RandomForest;

    [Range(0, 1)]
    public float? RfConfidenceThreshold { get; set; }


    [Range(0, 1)]
    public float? IfConfidenceThreshold { get; set; }

    [Range(1, 525600)]
    public int BlockDurationMinutes { get; set; } = 60;

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

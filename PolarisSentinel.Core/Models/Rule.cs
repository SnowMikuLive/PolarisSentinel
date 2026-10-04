using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// A firewall rule managed by Polaris Sentinel, created automatically from a policy
// decision or by hand. The firewall module owns persistence.
public class Rule
{
    public string Id { get; set; } = string.Empty;

    // Windows Firewall rule name (e.g. "PolarisSentinel_Block_A-RF-1").
    public string Name { get; set; } = string.Empty;

    // The policy that produced this rule; null for manual rules.
    public string? PolicyId { get; set; }

    // The alert that triggered this rule; null for manual rules.
    public string? AlertId { get; set; }

    public PolicyAction Action { get; set; }

    // 5-tuple the rule applies to.
    public string? SourceIp { get; set; } = string.Empty;

    public int? SourcePort { get; set; }

    public string? DestinationIp { get; set; } = string.Empty;

    public int? DestinationPort { get; set; }

    public byte? Protocol { get; set; }

    public RuleStatus Status { get; set; } = RuleStatus.Active;

    public DateTime CreatedAt { get; set; } = DateTime.Now;

    public DateTime UpdatedAt { get; set; } = DateTime.Now;

    public DateTime? ExpiresAt { get; set; }
}

using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// A firewall rule managed by Polaris Sentinel, created automatically from a policy
// decision or by hand. The firewall module owns persistence.
public class Rule
{
    public string Id { get; set; } = string.Empty;

    // Windows Firewall rule name, e.g. "PolarisSentinel_Block_BlockInboundIp_203.0.113.10".
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

    // The address the policy action blocks (null when the action blocks a port).
    public string? BlockedIp => Action switch
    {
        PolicyAction.BlockInboundIp => SourceIp,
        PolicyAction.BlockOutboundIp => DestinationIp,
        _ => null
    };

    // The port the policy action blocks (null when the action blocks an address).
    public int? BlockedPort => Action switch
    {
        PolicyAction.BlockInboundPort => DestinationPort,
        PolicyAction.BlockOutboundPort => DestinationPort,
        _ => null
    };

    public bool BlocksAddress => Action is PolicyAction.BlockInboundIp or PolicyAction.BlockOutboundIp;

    public bool BlocksOutbound => Action is PolicyAction.BlockOutboundIp or PolicyAction.BlockOutboundPort;
}

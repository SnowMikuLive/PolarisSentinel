using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// A firewall rule managed by Polaris Sentinel, created automatically from a policy
// decision or by hand. The firewall module owns persistence.
public class Rule
{
    public string Id { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    public string? PolicyId { get; set; }

    public string? AlertId { get; set; }

    public PolicyAction Action { get; set; }

    public string? SourceIp { get; set; } = string.Empty;

    public int? SourcePort { get; set; }

    public string? DestinationIp { get; set; } = string.Empty;

    public int? DestinationPort { get; set; }

    public byte? Protocol { get; set; }

    public RuleStatus Status { get; set; } = RuleStatus.Active;

    public DateTime CreatedAt { get; set; } = DateTime.Now;

    public DateTime UpdatedAt { get; set; } = DateTime.Now;

    public DateTime? ExpiresAt { get; set; }

    public string? BlockedIp => Action switch
    {
        PolicyAction.BlockInboundIp => SourceIp,
        PolicyAction.BlockOutboundIp => DestinationIp,
        _ => null
    };

    public int? BlockedPort => Action switch
    {
        PolicyAction.BlockInboundPort => DestinationPort,
        PolicyAction.BlockOutboundPort => DestinationPort,
        _ => null
    };

    public bool BlocksAddress => Action is PolicyAction.BlockInboundIp or PolicyAction.BlockOutboundIp;

    public bool BlocksOutbound => Action is PolicyAction.BlockOutboundIp or PolicyAction.BlockOutboundPort;
}

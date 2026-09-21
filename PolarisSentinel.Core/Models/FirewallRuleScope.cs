using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// Per-field scope of a firewall rule. Each field can either target the flow's
// exact value or match everything (Any), mirroring the policy's rule actions.
public class FirewallRuleScope
{
    public string SourceIp { get; set; } = string.Empty;

    public int SourcePort { get; set; }

    public string DestinationIp { get; set; } = string.Empty;

    public int DestinationPort { get; set; }

    // 0 = any protocol.
    public byte Protocol { get; set; }

    public static FirewallRuleScope Any { get; } = new();

    // Builds the scope from a policy's rule actions: Allow means the field is
    // left at Any, Block means the flow's exact value is used.
    public static FirewallRuleScope FromPolicy(
        Policy policy,
        string sourceIp,
        int sourcePort,
        string destinationIp,
        int destinationPort,
        byte protocol) => new()
        {
            SourceIp = policy.RuleSourceIpAction == PolicyAction.Block ? sourceIp ?? string.Empty : string.Empty,
            SourcePort = policy.RuleSourcePortAction == PolicyAction.Block ? sourcePort : 0,
            DestinationIp = policy.RuleDestinationIpAction == PolicyAction.Block ? destinationIp ?? string.Empty : string.Empty,
            DestinationPort = policy.RuleDestinationPortAction == PolicyAction.Block ? destinationPort : 0,
            Protocol = protocol
        };

    // True when no field is constrained, i.e. the rule blocks all traffic.
    public bool IsAny => string.IsNullOrWhiteSpace(SourceIp)
        && SourcePort == 0
        && string.IsNullOrWhiteSpace(DestinationIp)
        && DestinationPort == 0
        && Protocol == 0;

    // Applies the scope to an existing rule.
    public void ApplyTo(Rule rule)
    {
        rule.SourceIp = SourceIp ?? string.Empty;
        rule.SourcePort = SourcePort;
        rule.DestinationIp = DestinationIp ?? string.Empty;
        rule.DestinationPort = DestinationPort;
        rule.Protocol = Protocol;
    }
}

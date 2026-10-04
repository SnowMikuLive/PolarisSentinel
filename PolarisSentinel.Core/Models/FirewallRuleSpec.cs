using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// The concrete Windows Firewall rule a policy action maps to.
public class FirewallRuleSpec
{
    // 1 = inbound, 2 = outbound.
    public required int Direction { get; init; }

    // Remote address to constrain, or null for any.
    public string? RemoteAddress { get; init; }

    // Local port to constrain, or null for any.
    public int? LocalPort { get; init; }

    // Remote port to constrain, or null for any.
    public int? RemotePort { get; init; }

    public required byte Protocol { get; init; }

    // Validates a policy action against the alert and returns the rule to apply,
    // or an error message when the combination is not representable.
    public static FirewallRuleSpec? TryCreate(PolicyAction action, Alert alert, out string? error)
    {
        error = null;

        bool portAction = action is PolicyAction.BlockInboundPort or PolicyAction.BlockOutboundPort;
        // ICMP has no ports, so a port-based action cannot be expressed.
        if (portAction && alert.Protocol == ProtocolNumbers.Icmp)
        {
            error = "Port actions are not valid for ICMP; use an IP action instead.";
            return null;
        }

        // A port filter needs a concrete transport protocol; the Any protocol would
        // otherwise widen the rule to every port.
        if (portAction && alert.Protocol == 0)
        {
            error = "Port actions require a specific protocol (TCP or UDP), not Any.";
            return null;
        }

        return action switch
        {
            PolicyAction.BlockInboundIp => new FirewallRuleSpec
            {
                Direction = 1,
                RemoteAddress = alert.SourceIp,
                Protocol = alert.Protocol
            },
            PolicyAction.BlockInboundPort => new FirewallRuleSpec
            {
                Direction = 1,
                LocalPort = alert.DestinationPort,
                Protocol = alert.Protocol
            },
            PolicyAction.BlockOutboundIp => new FirewallRuleSpec
            {
                Direction = 2,
                RemoteAddress = alert.DestinationIp,
                Protocol = alert.Protocol
            },
            PolicyAction.BlockOutboundPort => new FirewallRuleSpec
            {
                Direction = 2,
                RemotePort = alert.DestinationPort,
                Protocol = alert.Protocol
            },
            _ => null
        };
    }
}

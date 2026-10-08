using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// The concrete Windows Firewall rule a policy action maps to, mirroring an Azure Network
// Security Group rule: an action selects a direction (inbound/outbound) and a match on
// either a remote address (IP) or a port.
public class FirewallRuleSpec
{
    // 1 = inbound, 2 = outbound.
    public required int Direction { get; init; }

    // Remote address to constrain, or null when the rule matches a port instead.
    public string? RemoteAddress { get; init; }

    // Local port to constrain, or null when the rule matches an address instead.
    public int? LocalPort { get; init; }

    // Remote port to constrain, or null when the rule matches an address instead.
    public int? RemotePort { get; init; }

    public required byte Protocol { get; init; }

    // Validates a policy action against the alert and returns the rule to apply,
    // or an error message when the combination is not representable.
    public static FirewallRuleSpec? TryCreate(PolicyAction action, Alert alert, out string? error) =>
        Create(action, alert.SourceIp, alert.DestinationIp, alert.DestinationPort, alert.Protocol, out error);

    // Rebuilds the spec for a persisted rule (its 5-tuple mirrors the originating alert).
    // Null when the rule's action/protocol combination is not representable as a rule.
    public static FirewallRuleSpec? FromRule(Rule rule) =>
        Create(rule.Action, rule.SourceIp ?? string.Empty, rule.DestinationIp ?? string.Empty,
            rule.DestinationPort ?? 0, rule.Protocol ?? 0, out _);

    private static FirewallRuleSpec? Create(
        PolicyAction action, string sourceIp, string destinationIp, int destinationPort, byte protocol, out string? error)
    {
        error = null;

        bool portAction = action is PolicyAction.BlockInboundPort or PolicyAction.BlockOutboundPort;
        // ICMP has no ports, so a port-based action cannot be expressed.
        if (portAction && protocol == ProtocolNumbers.Icmp)
        {
            error = "Port actions are not valid for ICMP; use an IP action instead.";
            return null;
        }

        // A port filter needs a concrete transport protocol; the Any protocol would
        // otherwise widen the rule to every port.
        if (portAction && protocol == 0)
        {
            error = "Port actions require a specific protocol (TCP or UDP), not Any.";
            return null;
        }

        return action switch
        {
            // An address block is protocol-agnostic so it covers the whole host.
            PolicyAction.BlockInboundIp => new FirewallRuleSpec { Direction = 1, RemoteAddress = sourceIp, Protocol = 0 },
            PolicyAction.BlockOutboundIp => new FirewallRuleSpec { Direction = 2, RemoteAddress = destinationIp, Protocol = 0 },
            PolicyAction.BlockInboundPort => new FirewallRuleSpec { Direction = 1, LocalPort = destinationPort, Protocol = protocol },
            PolicyAction.BlockOutboundPort => new FirewallRuleSpec { Direction = 2, RemotePort = destinationPort, Protocol = protocol },
            _ => null
        };
    }
}

using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

public class FirewallRuleSpec
{
    public required int Direction { get; init; }

    public string? RemoteAddress { get; init; }

    public int? LocalPort { get; init; }

    public int? RemotePort { get; init; }

    public required byte Protocol { get; init; }

    public static FirewallRuleSpec? TryCreate(PolicyAction action, Alert alert, out string? error) =>
        Create(action, alert.SourceIp, alert.DestinationIp, alert.DestinationPort, alert.Protocol, out error);

    public static FirewallRuleSpec? FromRule(Rule rule) =>
        Create(rule.Action, rule.SourceIp ?? string.Empty, rule.DestinationIp ?? string.Empty,
            rule.DestinationPort ?? 0, rule.Protocol ?? 0, out _);

    private static FirewallRuleSpec? Create(
        PolicyAction action, string sourceIp, string destinationIp, int destinationPort, byte protocol, out string? error)
    {
        error = null;

        bool portAction = action is PolicyAction.BlockInboundPort or PolicyAction.BlockOutboundPort;
        if (portAction && protocol == ProtocolNumbers.Icmp)
        {
            error = "Port actions are not valid for ICMP; use an IP action instead.";
            return null;
        }

        if (portAction && protocol == 0)
        {
            error = "Port actions require a specific protocol (TCP or UDP), not Any.";
            return null;
        }

        return action switch
        {
            PolicyAction.BlockInboundIp => new FirewallRuleSpec { Direction = 1, RemoteAddress = sourceIp, Protocol = 0 },
            PolicyAction.BlockOutboundIp => new FirewallRuleSpec { Direction = 2, RemoteAddress = destinationIp, Protocol = 0 },
            PolicyAction.BlockInboundPort => new FirewallRuleSpec { Direction = 1, LocalPort = destinationPort, Protocol = protocol },
            PolicyAction.BlockOutboundPort => new FirewallRuleSpec { Direction = 2, RemotePort = destinationPort, Protocol = protocol },
            _ => null
        };
    }
}

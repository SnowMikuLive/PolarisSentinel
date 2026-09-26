using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Constants;

// Helpers for the policy action set.
public static class PolicyActions
{
    // The four actions that produce a firewall rule.
    public static readonly PolicyAction[] Blocking =
    {
        PolicyAction.BlockInboundIp,
        PolicyAction.BlockInboundPort,
        PolicyAction.BlockOutboundIp,
        PolicyAction.BlockOutboundPort
    };

    // True when the action should create or update a firewall rule.
    public static bool IsBlocking(PolicyAction action) => Array.IndexOf(Blocking, action) >= 0;
}

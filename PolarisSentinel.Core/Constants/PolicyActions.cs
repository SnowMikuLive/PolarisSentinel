using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Constants;

public static class PolicyActions
{
    public static readonly PolicyAction[] Blocking =
    {
        PolicyAction.BlockInboundIp,
        PolicyAction.BlockInboundPort,
        PolicyAction.BlockOutboundIp,
        PolicyAction.BlockOutboundPort
    };

    public static bool IsBlocking(PolicyAction action) => Array.IndexOf(Blocking, action) >= 0;
}

namespace PolarisSentinel.Core.Enums;

public enum PolicyAction
{
    // No action required, traffic is treated as benign.
    Allow,

    // Log and surface the event on the Dashboard without touching the firewall.
    Monitor,

    // Block the alert's source IP with an inbound rule.
    BlockInboundIp,

    // Block the alert's destination port with an inbound rule.
    BlockInboundPort,

    // Block the alert's destination IP with an outbound rule.
    BlockOutboundIp,

    // Block the alert's destination port with an outbound rule.
    BlockOutboundPort
}

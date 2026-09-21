namespace PolarisSentinel.Core.Enums;

public enum PolicyAction
{
    //No action required, traffic is treated as benign.
    Allow,

    //Log and surface the event on the Dashboard
    Monitor,

    //Create a Windows Firewall rule blocking the source IP address.
    Block
}

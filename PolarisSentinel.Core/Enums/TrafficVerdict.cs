namespace PolarisSentinel.Core.Enums;

// Mutually exclusive outcome of one captured flow, used for the dashboard chart.
public enum TrafficVerdict
{
    Normal,

    Suspicious,

    Malicious,

    Blocked
}

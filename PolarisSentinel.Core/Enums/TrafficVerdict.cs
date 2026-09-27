namespace PolarisSentinel.Core.Enums;

// Mutually exclusive outcome of one captured flow, used for the dashboard chart.
public enum TrafficVerdict
{
    // The flow was classified as benign and produced no alert.
    Normal,

    // The flow was suspicious or anomalous but did not reach the alert threshold.
    Suspicious,

    // The flow produced an alert.
    Malicious
}

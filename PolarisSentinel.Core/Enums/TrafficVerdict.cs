namespace PolarisSentinel.Core.Enums;

// Mutually exclusive outcome of one captured flow, used for the dashboard chart.
public enum TrafficVerdict
{
    // The flow was classified as benign and produced no alert.
    Normal,

    // The flow was suspicious: it entered the AI engine but the inference result was not a
    // confirmed attack (an unnamed anomaly, or below the alert threshold). Also used for a
    // heuristic known attack that the model did not confirm as malicious.
    Suspicious,

    // The flow was confirmed malicious: the AI inference result was a named attack category
    // (DoS / PortScan / BruteForce), or the heuristic pre-filter recognised a known attack.
    Malicious
}

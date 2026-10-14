namespace PolarisSentinel.Core.Enums;

// Detection sensitivity preset. Higher sensitivity lowers the heuristic thresholds so
// attacks are caught sooner, at the cost of more false positives. The individual
// threshold values live in DetectionThresholds.
public enum DetectionSensitivity
{
    Low,

    Balanced,

    High
}

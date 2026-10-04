namespace PolarisSentinel.Core.Enums;

public enum DetectionSource
{
    //No attack detected by either model.
    None,

    //Result came from the supervised Random Forest classifier (known attack type).
    RandomForest,

    //Result came from the unsupervised Isolation Forest anomaly detector.
    IsolationForest,

    //Result came from the rule-based heuristic detector in the capture layer.
    HeuristicBased
}

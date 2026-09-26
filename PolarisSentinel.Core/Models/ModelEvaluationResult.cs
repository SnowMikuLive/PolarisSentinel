using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// One labeled test row: the flow features plus its ground-truth label.
public class LabeledFlow
{
    public required FlowFeatureVector Flow { get; init; }

    // True for any attack label, false for benign.
    public required bool IsMalicious { get; init; }
}

// The metrics one model combination achieved over the test set.
public class ModelEvaluationResult
{
    public required ModelCombination Combination { get; init; }

    public required EvaluationMetrics Metrics { get; init; }
}

using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// One labeled test row: the flow features plus its ground-truth label.
public class LabeledFlow
{
    public required FlowFeatureVector Flow { get; init; }

    public required bool IsMalicious { get; init; }
}

public class ModelEvaluationResult
{
    public required ModelCombination Combination { get; init; }

    public required EvaluationMetrics Metrics { get; init; }
}

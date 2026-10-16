using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

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

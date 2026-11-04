using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Application.Evaluation;

public class EvaluationService
{
    private readonly IModelCombinationService _combinations;

    public EvaluationService(IModelCombinationService combinations)
    {
        _combinations = combinations;
    }

    public IReadOnlyList<ModelEvaluationResult> EvaluateAll(
        IReadOnlyList<LabeledFlow> rows,
        IReadOnlyList<ModelCombination>? combinations = null)
    {
        var selected = combinations ?? _combinations.AvailableCombinations;
        var results = new List<ModelEvaluationResult>();

        foreach (var combination in selected)
        {
            var (tp, tn, fp, fn) = CountOutcomes(rows, combination);

            results.Add(new ModelEvaluationResult
            {
                Combination = combination,
                Metrics = new EvaluationMetrics
                {
                    TruePositives = tp,
                    TrueNegatives = tn,
                    FalsePositives = fp,
                    FalseNegatives = fn
                }
            });
        }

        return results;
    }

    private (int TruePositives, int TrueNegatives, int FalsePositives, int FalseNegatives) CountOutcomes(
        IReadOnlyList<LabeledFlow> rows,
        ModelCombination combination)
    {
        int tp = 0, tn = 0, fp = 0, fn = 0;

        foreach (var row in rows)
        {
            var prediction = _combinations.Run(row.Flow, combination);
            bool predictedMalicious = prediction.AttackType != AttackTypes.Benign;

            if (row.IsMalicious)
            {
                if (predictedMalicious) tp++;
                else fn++;
            }
            else
            {
                if (predictedMalicious) fp++;
                else tn++;
            }
        }

        return (tp, tn, fp, fn);
    }
}

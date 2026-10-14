using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Application.Evaluation;

// Compares the five AI model combinations on a labeled test set.
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
        var selected = combinations ?? ModelCombinations.All;
        var results = new List<ModelEvaluationResult>();

        foreach (var combination in selected)
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
}

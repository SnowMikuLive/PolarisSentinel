using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Inference;

// Executes the five AI engine configurations over the Random Forest and Isolation Forest models.
public class ModelCombinationService : IModelCombinationService
{
    private readonly IRandomForestModel _randomForest;
    private readonly IIsolationForestModel? _isolationForest;
    private readonly object _lock = new();

    private ModelCombination _active;

    public ModelCombinationService(
        IRandomForestModel randomForest,
        IIsolationForestModel? isolationForest,
        ModelCombination active = ModelCombination.RandomForestOnly)
    {
        _randomForest = randomForest;
        _isolationForest = isolationForest;
        _active = active;
    }

    public ModelCombination ActiveCombination
    {
        get
        {
            lock (_lock)
            {
                return _active;
            }
        }
    }

    public void SetActiveCombination(ModelCombination combination)
    {
        lock (_lock)
        {
            _active = combination;
        }
    }

    public InferenceResult Run(FlowFeatureVector flow, ModelCombination? combination = null)
    {
        var selected = combination ?? ActiveCombination;
        if (selected != ModelCombination.RandomForestOnly && _isolationForest == null)
        {
            throw new InvalidOperationException(
                $"Model combination {selected} requires the Isolation Forest model, which is not loaded.");
        }

        return selected switch
        {
            ModelCombination.RandomForestOnly => RandomForestOnly(flow),
            ModelCombination.IsolationForestOnly => IsolationForestOnly(flow),
            ModelCombination.IsolationThenRandomForest => IsolationThenRandomForest(flow),
            ModelCombination.RandomForestThenIsolation => RandomForestThenIsolation(flow),
            ModelCombination.ParallelRandomForestAndIsolation => Parallel(flow),
            _ => throw new ArgumentOutOfRangeException(nameof(combination), selected, null)
        };
    }

    private InferenceResult RandomForestOnly(FlowFeatureVector flow)
    {
        var result = _randomForest.Classify(flow);
        return result.AttackType == AttackTypes.Benign ? InferenceResult.Benign() : result;
    }

    private InferenceResult IsolationForestOnly(FlowFeatureVector flow)
    {
        return _isolationForest!.IsAnomaly(flow) ? _isolationForest.Score(flow) : InferenceResult.Benign();
    }

    private InferenceResult IsolationThenRandomForest(FlowFeatureVector flow)
    {
        if (!_isolationForest!.IsAnomaly(flow))
        {
            return InferenceResult.Benign();
        }

        var result = _randomForest.Classify(flow);
        // IF flagged an anomaly but RF cannot name a known attack: report the anomaly itself.
        if (result.AttackType == AttackTypes.Benign)
        {
            return _isolationForest.Score(flow);
        }
        return result;
    }

    private InferenceResult RandomForestThenIsolation(FlowFeatureVector flow)
    {
        var result = _randomForest.Classify(flow);
        // RF only wins when it reports a known attack with enough confidence.
        if (result.AttackType != AttackTypes.Benign && _randomForest.ExceedsThreshold(result))
        {
            return result;
        }

        if (_isolationForest!.IsAnomaly(flow))
        {
            return _isolationForest.Score(flow);
        }

        return InferenceResult.Benign(_randomForest.BenignProbability(flow));
    }

    private InferenceResult Parallel(FlowFeatureVector flow)
    {
        var result = _randomForest.Classify(flow);
        // A known attack from RF wins; otherwise fall back to the anomaly verdict.
        if (result.AttackType != AttackTypes.Benign)
        {
            return result;
        }

        return _isolationForest!.IsAnomaly(flow) ? _isolationForest.Score(flow) : InferenceResult.Benign();
    }
}

using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Application;

public class ModelCombinationService : IModelCombinationService
{
    private readonly IRandomForestModel _randomForest;
    private readonly IIsolationForestModel? _isolationForest;
    private readonly IUserSettingsStore? _settings;
    private readonly object _lock = new();

    private ModelCombination _active;

    public ModelCombinationService(
        IRandomForestModel randomForest,
        IIsolationForestModel? isolationForest,
        ModelCombination active = ModelCombination.RandomForestOnly,
        IUserSettingsStore? settings = null)
    {
        _randomForest = randomForest;
        _isolationForest = isolationForest;
        _settings = settings;

        if (settings?.Read().ModelCombination is { } saved)
        {
            active = Enum.TryParse<ModelCombination>(saved, out var restored) && IsAvailable(restored)
                ? restored : ModelCombination.RandomForestOnly;
        }

        _active = IsAvailable(active) ? active : ModelCombination.RandomForestOnly;
    }

    public IReadOnlyList<ModelCombination> AvailableCombinations =>
        ModelCombinations.All.Where(IsAvailable).ToArray();

    private bool IsAvailable(ModelCombination combination) =>
        Enum.IsDefined(combination) && (combination == ModelCombination.RandomForestOnly || _isolationForest is not null);

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
        if (!IsAvailable(combination))
            throw new ArgumentException("Unknown model combination, or its Isolation Forest model is not available.", nameof(combination));
        lock (_lock)
        {
            _settings?.Update(s => s.ModelCombination = combination.ToString());
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
        if (result.AttackType == AttackTypes.Benign)
        {
            return _isolationForest.Score(flow);
        }
        return result;
    }

    private InferenceResult RandomForestThenIsolation(FlowFeatureVector flow)
    {
        var result = _randomForest.Classify(flow);
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
        if (result.AttackType != AttackTypes.Benign)
        {
            return result;
        }

        return _isolationForest!.IsAnomaly(flow) ? _isolationForest.Score(flow) : InferenceResult.Benign();
    }
}

using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IRandomForestModel
{
    InferenceResult Classify(FlowFeatureVector flow);

    bool ExceedsThreshold(InferenceResult result);

    float BenignProbability(FlowFeatureVector flow);
}

public interface IIsolationForestModel
{
    bool IsAnomaly(FlowFeatureVector flow);

    InferenceResult Score(FlowFeatureVector flow);
}

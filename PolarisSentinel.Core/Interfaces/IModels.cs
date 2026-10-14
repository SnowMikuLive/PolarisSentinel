using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Runs the Random Forest classifier on one flow.
public interface IRandomForestModel
{
    InferenceResult Classify(FlowFeatureVector flow);

    bool ExceedsThreshold(InferenceResult result);

    float BenignProbability(FlowFeatureVector flow);
}

// Runs the Isolation Forest anomaly detector on one flow.
public interface IIsolationForestModel
{
    bool IsAnomaly(FlowFeatureVector flow);

    InferenceResult Score(FlowFeatureVector flow);
}

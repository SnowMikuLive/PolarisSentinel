using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Runs the Random Forest classifier on one flow.
public interface IRandomForestModel
{
    // Returns the most likely attack category and its probability.
    InferenceResult Classify(FlowFeatureVector flow);

    // True when the result is a known attack at or above the model's confidence threshold.
    bool ExceedsThreshold(InferenceResult result);

    // The classifier's probability for the benign class.
    float BenignProbability(FlowFeatureVector flow);
}

// Runs the Isolation Forest anomaly detector on one flow.
public interface IIsolationForestModel
{
    // True when the flow is anomalous according to the model's anomaly threshold.
    bool IsAnomaly(FlowFeatureVector flow);

    // Returns a normalized anomaly score where a higher value means stronger anomaly evidence.
    InferenceResult Score(FlowFeatureVector flow);
}

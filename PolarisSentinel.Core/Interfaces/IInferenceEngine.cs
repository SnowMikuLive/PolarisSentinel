using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Runs the configured AI model combination over a flow and produces a detection result.
public interface IInferenceEngine
{
    // Runs the active model combination and returns the resulting alert.
    Alert Detect(FlowFeatureVector flow);

    // Runs a specific model combination without touching the live configuration.
    Alert Detect(FlowFeatureVector flow, Enums.ModelCombination combination);
}

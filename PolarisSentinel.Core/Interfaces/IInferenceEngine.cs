using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Runs the configured AI model combination over a flow and produces a detection result.
public interface IInferenceEngine
{
    Alert Detect(FlowFeatureVector flow);

    Alert Detect(FlowFeatureVector flow, Enums.ModelCombination combination);
}

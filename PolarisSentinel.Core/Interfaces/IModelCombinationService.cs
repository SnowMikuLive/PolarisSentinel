using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Executes one of the five AI engine configurations over a flow.
public interface IModelCombinationService
{
    // The configuration currently used by the live detection pipeline.
    ModelCombination ActiveCombination { get; }

    // Switch the live configuration. Does not affect any in-flight flow.
    void SetActiveCombination(ModelCombination combination);

    // Run the given configuration (defaults to the active one) and return its verdict.
    InferenceResult Run(FlowFeatureVector flow, ModelCombination? combination = null);
}

using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Executes one of the five AI engine configurations over a flow.
public interface IModelCombinationService
{
    ModelCombination ActiveCombination { get; }

    void SetActiveCombination(ModelCombination combination);

    InferenceResult Run(FlowFeatureVector flow, ModelCombination? combination = null);
}

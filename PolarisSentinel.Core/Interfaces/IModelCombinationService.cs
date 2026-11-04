using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IModelCombinationService
{
    IReadOnlyList<ModelCombination> AvailableCombinations { get; }
    ModelCombination ActiveCombination { get; }

    void SetActiveCombination(ModelCombination combination);

    InferenceResult Run(FlowFeatureVector flow, ModelCombination? combination = null);
}

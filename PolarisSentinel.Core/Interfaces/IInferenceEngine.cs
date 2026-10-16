using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IInferenceEngine
{
    Alert Detect(FlowFeatureVector flow);

    Alert Detect(FlowFeatureVector flow, Enums.ModelCombination combination);
}

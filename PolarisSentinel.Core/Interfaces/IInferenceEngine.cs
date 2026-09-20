using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IInferenceEngine
{
    Alert Detect(FlowFeatureVector flow);
}

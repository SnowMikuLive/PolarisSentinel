using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IInferenceEngine
{
    DetectionResult Detect(FlowFeatureVector flow);
}

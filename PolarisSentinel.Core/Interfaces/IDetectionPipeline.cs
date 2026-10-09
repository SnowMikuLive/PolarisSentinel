using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Application-layer detection pipeline contract.
public interface IDetectionPipeline
{
    DetectionOutcome ProcessFlow(FlowFeatureVector flow, IReadOnlyList<Policy> policies);
}

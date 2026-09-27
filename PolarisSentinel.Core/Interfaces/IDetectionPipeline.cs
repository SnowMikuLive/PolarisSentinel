using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Application-layer detection pipeline contract.
public interface IDetectionPipeline
{
    // Runs one captured flow through pre-filter, AI (when needed), policy and enforcement.
    DetectionOutcome ProcessFlow(FlowFeatureVector flow, IReadOnlyList<Policy> policies);
}

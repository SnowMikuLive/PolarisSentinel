using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IDetectionPipeline
{
    DetectionOutcome ProcessFlow(FlowFeatureVector flow, IReadOnlyList<Policy> policies);
}

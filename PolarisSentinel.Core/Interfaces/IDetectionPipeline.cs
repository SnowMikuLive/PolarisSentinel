using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Application-layer detection pipeline contract.
public interface IDetectionPipeline
{
    Alert ProcessFlow(FlowFeatureVector flow, Policy policy);
}

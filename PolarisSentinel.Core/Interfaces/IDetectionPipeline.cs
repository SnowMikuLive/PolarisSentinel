using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Application-layer use case: orchestrates a completed flow through the
// detection -> decision -> enforcement pipeline and returns the final decision.
public interface IDetectionPipeline
{
    // Processes one completed flow and returns the resulting policy decision.
    PolicyDecision ProcessFlow(FlowFeatureVector flow);
}

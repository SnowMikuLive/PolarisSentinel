using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Classifies a flow's features into an attack type and confidence.
public interface IInferenceEngine
{
    // Run inference and return an alert carrying the 5-tuple and the detected attack type.
    Alert Detect(FlowFeatureVector flow);
}

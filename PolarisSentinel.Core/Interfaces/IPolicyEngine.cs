using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IPolicyEngine
{
    PolicyDecision Evaluate(DetectionResult result);

    //Reloads the current policy configuration
    Task RefreshSettingsAsync();
}

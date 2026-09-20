using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IPolicyEngine
{
    Policy Evaluate(Alert result);

    //Reloads the current policy configuration
    Task RefreshSettingsAsync();
}

using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Maps an alert onto a policy action.
public interface IPolicyEngine
{
    // Evaluate an alert against the owner's policy and return it with the decision applied.
    Alert Evaluate(Alert alert, Policy policy);

    // Seed the alert id counter from existing alerts so ids do not collide after a restart.
    void InitializeAlertCounter(int maxExistingNumber);
}

using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Evaluates an alert against the enabled policies and returns the action to apply.
public interface IPolicyEngine
{
    PolicyDecision Evaluate(Alert alert, IReadOnlyList<Policy> policies);
}

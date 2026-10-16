using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IPolicyEngine
{
    PolicyDecision Evaluate(Alert alert, IReadOnlyList<Policy> policies);
}

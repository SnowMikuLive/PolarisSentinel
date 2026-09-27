using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// The action the policy engine decided should be applied to a matching alert.
public class PolicyDecision
{
    // The policy that produced this decision, or null when no policy matched.
    public string? PolicyId { get; init; }

    public PolicyAction Action { get; init; } = PolicyAction.Monitor;

    public int BlockDurationMinutes { get; init; }

    public string Reason { get; init; } = string.Empty;

    // The alert this decision was made for.
    public required Alert Alert { get; init; }

    public static PolicyDecision Monitor(Alert alert, string reason) =>
        new() { Alert = alert, Action = PolicyAction.Monitor, Reason = reason };

    public static PolicyDecision Block(Alert alert, Policy policy, string reason) =>
        new()
        {
            Alert = alert,
            PolicyId = policy.Id,
            Action = policy.Action,
            BlockDurationMinutes = policy.BlockDurationMinutes,
            Reason = reason
        };
}

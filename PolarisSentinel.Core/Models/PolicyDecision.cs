using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// The action the policy engine decided should be applied to a matching alert.
public class PolicyDecision
{
    // The policy that produced this decision, or null when no policy matched.
    public string? PolicyId { get; init; }

    // The name of the matched policy, shown alongside the decision for context.
    public string? PolicyName { get; init; }

    public PolicyAction Action { get; init; } = PolicyAction.Monitor;

    public int BlockDurationMinutes { get; init; }

    // Stable machine code for the decision (see DecisionReasons).
    public string Reason { get; init; } = string.Empty;

    // Plain-language explanation of the decision, surfaced in the UI.
    public string ReasonText { get; init; } = string.Empty;

    // The alert this decision was made for.
    public required Alert Alert { get; init; }

    public static PolicyDecision Monitor(Alert alert, string reason) =>
        new()
        {
            Alert = alert,
            Action = PolicyAction.Monitor,
            Reason = reason,
            ReasonText = Constants.DecisionReasons.Describe(reason)
        };

    public static PolicyDecision Block(Alert alert, Policy policy, string reason) =>
        new()
        {
            Alert = alert,
            PolicyId = policy.Id,
            PolicyName = policy.Name,
            Action = policy.Action,
            BlockDurationMinutes = policy.BlockDurationMinutes,
            Reason = reason,
            ReasonText = Constants.DecisionReasons.Describe(reason)
        };
}

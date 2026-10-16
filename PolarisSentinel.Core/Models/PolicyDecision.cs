using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

public class PolicyDecision
{
    public string? PolicyId { get; init; }

    public string? PolicyName { get; init; }

    public PolicyAction Action { get; init; } = PolicyAction.Monitor;

    public int BlockDurationMinutes { get; init; }

    public string Reason { get; init; } = string.Empty;

    public string ReasonText { get; init; } = string.Empty;

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

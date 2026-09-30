using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Application;

// Matches an alert against the enabled policies and decides what should happen.
public class PolicyEngine : IPolicyEngine
{
    private readonly ILogger<PolicyEngine> _logger;

    public PolicyEngine(ILogger<PolicyEngine> logger)
    {
        _logger = logger;
    }

    public PolicyDecision Evaluate(Alert alert, IReadOnlyList<Policy> policies)
    {
        if (alert == null)
        {
            throw new ArgumentNullException(nameof(alert));
        }

        if (alert.DetectionSource == DetectionSource.None || alert.AttackType == AttackTypes.Benign)
        {
            return PolicyDecision.Monitor(alert, "benign");
        }

        // 未知异常只告警，由人工决定是否封禁。
        // Unknown anomalies are monitored for a human decision.
        if (alert.AttackType == AttackTypes.UnknownAnomaly)
        {
            return PolicyDecision.Monitor(alert, "unknown_anomaly");
        }

        var match = SelectPolicy(alert, policies);
        if (match == null)
        {
            return PolicyDecision.Monitor(alert, "no_matching_policy");
        }

        if (!PolicyActions.IsBlocking(match.Action))
        {
            return PolicyDecision.Monitor(alert, match.Action == PolicyAction.Allow ? "policy_allow" : "policy_monitor");
        }

        _logger.LogDebug(
            "Policy {PolicyId} blocked {AttackType} from {SourceIp}",
            match.Id, alert.AttackType, alert.SourceIp);

        return PolicyDecision.Block(alert, match, "policy_block");
    }

    // Highest priority wins; ties fall back to the older policy, then the id, for determinism.
    private static Policy? SelectPolicy(Alert alert, IReadOnlyList<Policy> policies)
    {
        return policies
            .Where(p => p.IsEnabled && Matches(alert, p))
            .OrderByDescending(p => p.Priority)
            .ThenBy(p => p.CreatedAt)
            .ThenBy(p => p.Id, StringComparer.Ordinal)
            .FirstOrDefault();
    }

    private static bool Matches(Alert alert, Policy policy)
    {
        if (policy.DetectionSource is { } source && source != alert.DetectionSource)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(policy.AttackType) &&
            !string.Equals(policy.AttackType, alert.AttackType, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return MeetsThreshold(alert, policy);
    }

    // The threshold that applies is the one belonging to the detector that produced the alert.
    private static bool MeetsThreshold(Alert alert, Policy policy)
    {
        if (alert.DetectionSource == DetectionSource.PreFilter)
        {
            return true;
        }

        float? threshold = alert.DetectionSource switch
        {
            DetectionSource.RandomForest => policy.RfThreshold,
            DetectionSource.IsolationForest => policy.IfThreshold,
            _ => null
        };

        return threshold is null || alert.ConfidenceScore is { } score && score >= threshold;
    }
}

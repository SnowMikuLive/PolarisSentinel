using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using Decision = PolarisSentinel.Core.Models.PolicyDecision;

namespace PolarisSentinel.PolicyDecision;

// Matches an alert against the enabled policies and decides what should happen.
public class PolicyEngine : IPolicyEngine
{
    private readonly ILogger<PolicyEngine> _logger;

    public PolicyEngine(ILogger<PolicyEngine> logger)
    {
        _logger = logger;
    }

    public Decision Evaluate(Alert alert, IReadOnlyList<Policy> policies)
    {
        if (alert == null)
        {
            throw new ArgumentNullException(nameof(alert));
        }

        if (alert.DetectionSource == DetectionSource.IsolationForest)
        {
            alert.AttackType = AttackTypes.UnknownAnomaly;
        }

        if (alert.DetectionSource == DetectionSource.None || alert.AttackType == AttackTypes.Benign)
        {
            return Decision.Monitor(alert, DecisionReasons.Benign);
        }

        if (alert.AttackType == AttackTypes.UnknownAnomaly)
        {
            return Decision.Monitor(alert, DecisionReasons.UnknownAnomaly);
        }

        if (alert.SpoofedSource)
        {
            return Decision.Monitor(alert, DecisionReasons.SpoofedSource);
        }

        var match = SelectPolicy(alert, policies);
        if (match == null)
        {
            return Decision.Monitor(alert, DecisionReasons.NoMatchingPolicy);
        }

        if (!PolicyActions.IsBlocking(match.Action))
        {
            return Decision.Monitor(alert, match.Action == PolicyAction.Allow
                ? DecisionReasons.PolicyAllow
                : DecisionReasons.PolicyMonitor);
        }

        _logger.LogDebug(
            "Policy {PolicyId} blocked {AttackType} from {SourceIp}",
            match.Id, alert.AttackType, alert.SourceIp);

        return Decision.Block(alert, match, DecisionReasons.PolicyBlock);
    }

    private static Policy? SelectPolicy(Alert alert, IReadOnlyList<Policy> policies)
    {
        return policies
            .Where(p => p.IsEnabled && p.Matches(alert))
            .OrderByDescending(p => p.Priority)
            .ThenBy(p => p.CreatedAt)
            .ThenBy(p => p.Id, StringComparer.Ordinal)
            .FirstOrDefault();
    }
}

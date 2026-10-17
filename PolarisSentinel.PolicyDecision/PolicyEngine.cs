using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using Decision = PolarisSentinel.Core.Models.PolicyDecision;

namespace PolarisSentinel.PolicyDecision;

public class PolicyEngine : IPolicyEngine
{
    private readonly ILogger<PolicyEngine> _logger;

    public PolicyEngine(ILogger<PolicyEngine> logger)
    {
        _logger = logger;
    }

    public Decision Evaluate(Alert alert, IReadOnlyList<Policy> policies)
    {
        ArgumentNullException.ThrowIfNull(alert);

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

        if (_logger.IsEnabled(LogLevel.Debug))
        {
            _logger.LogDebug(
                "Policy {PolicyId} blocked {AttackType} from {SourceIp}",
                match.Id, alert.AttackType, alert.SourceIp);
        }

        return Decision.Block(alert, match, DecisionReasons.PolicyBlock);
    }

    private static Policy? SelectPolicy(Alert alert, IReadOnlyList<Policy> policies)
    {
        return policies
            .Where(p => p.IsEnabled && p.Matches(alert))
            .OrderByDescending(p => p.Priority)
            .ThenBy(p => p.CreatedAt)
            .ThenBy(p => NumericSuffix(p.Id))
            .ThenBy(p => p.Id, StringComparer.Ordinal)
            .FirstOrDefault();
    }

    private static int NumericSuffix(string? id)
    {
        if (string.IsNullOrEmpty(id))
        {
            return int.MaxValue;
        }

        int index = id.Length;
        while (index > 0 && char.IsDigit(id[index - 1]))
        {
            index--;
        }

        if (index == id.Length)
        {
            return int.MaxValue;
        }

        return int.TryParse(id.AsSpan(index), out int value) ? value : int.MaxValue;
    }
}

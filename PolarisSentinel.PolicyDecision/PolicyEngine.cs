using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.PolicyDecision
{
    public class PolicyEngine : IPolicyEngine
    {
        private readonly TimeProvider _timeProvider;
        private readonly ILogger<PolicyEngine> _logger;
        private readonly object _lock = new object();
        private int _alertCounter;

        public PolicyEngine(TimeProvider timeProvider, ILogger<PolicyEngine> logger)
        {
            _timeProvider = timeProvider;
            _logger = logger;
        }

        public Alert Evaluate(Alert alert, Policy policy)
        {
            if (alert == null)
            {
                throw new ArgumentNullException(nameof(alert));
            }
            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            lock (_lock)
            {
                var now = _timeProvider.GetLocalNow().DateTime;

                if (alert.Source == DetectionSource.None || alert.AttackType == AttackTypes.Benign)
                {
                    return CreateDecision(alert, PolicyAction.Monitor, "benign", now);
                }

                if (!MatchesCriteria(alert, policy))
                {
                    return CreateDecision(alert, PolicyAction.Monitor, "no_match", now);
                }

                return CreateDecision(alert, PolicyAction.Block, "attack_detected", now);
            }
        }

        public void InitializeAlertCounter(int maxExistingNumber)
        {
            lock (_lock)
            {
                if (maxExistingNumber > _alertCounter)
                {
                    _alertCounter = maxExistingNumber;
                }
            }
            _logger.LogInformation("Alert counter initialised at {Counter}", _alertCounter);
        }

        private static bool MatchesCriteria(Alert alert, Policy policy)
        {
            if (!MatchesAttackType(alert.AttackType, policy.MatchAttackTypes))
            {
                return false;
            }

            if (policy.MatchProtocol != 0 && alert.Protocol != policy.MatchProtocol)
            {
                return false;
            }

            return true;
        }

        private static bool MatchesAttackType(string? attackType, string? configured)
        {
            if (string.IsNullOrWhiteSpace(configured))
            {
                return true;
            }

            var entries = configured.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            return entries.Any(e => string.Equals(e, attackType, StringComparison.OrdinalIgnoreCase));
        }

        private Alert CreateDecision(Alert alert, PolicyAction action, string reason, DateTime now)
        {
            alert.Id = EntityIds.Alert(alert.Source, ++_alertCounter);
            alert.Action = action;
            alert.DecidedAt = now;
            alert.Reason = reason;

            _logger.LogDebug(
                "Policy decision {AlertId}: {Action} for {SourceIp}, attack {AttackType}, confidence {Confidence}, reason {Reason}",
                alert.Id, alert.Action, alert.SourceIp, alert.AttackType, alert.Confidence, alert.Reason);

            return alert;
        }
    }
}

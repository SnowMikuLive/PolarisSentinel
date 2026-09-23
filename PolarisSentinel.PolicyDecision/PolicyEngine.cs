using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.PolicyDecision
{
    //按策略匹配结果写回Block/Monitor，并为告警分配NewId主键。
    //Apply Block/Monitor from policy match criteria;assign NewId on the alert.
    public class PolicyEngine : IPolicyEngine
    {
        private readonly TimeProvider _timeProvider;
        private readonly ILogger<PolicyEngine> _logger;
        private readonly object _lock = new object();

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

                // 未知异常只告警，不自动封禁。
                // Unknown anomalies are Monitor-only.
                if (alert.AttackType == AttackTypes.UnknownAnomaly)
                {
                    return CreateDecision(alert, PolicyAction.Monitor, "unknown_anomaly_monitor_only", now);
                }

                if (!MatchesCriteria(alert, policy))
                {
                    return CreateDecision(alert, PolicyAction.Monitor, "no_match", now);
                }

                return CreateDecision(alert, PolicyAction.Block, "attack_detected", now);
            }
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
            //决策落库前生成GUID，旧A-RF-n等历史行不受影响。
            //Assign a GUID before persistence;legacy A-RF-n rows stay as-is.
            alert.Id = EntityIds.NewId();
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

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
        private readonly string[] _allowlist;

        public PolicyEngine(TimeProvider timeProvider, ILogger<PolicyEngine> logger, string[]? allowlist = null)
        {
            _timeProvider = timeProvider;
            _logger = logger;
            _allowlist = allowlist ?? Array.Empty<string>();
        }

        // 检测之后再选策略，具体条件优先，同分按创建时间和编号排序。
        // Select after detection; specific criteria win, then creation time and ID.
        public Policy? SelectPolicy(IReadOnlyList<Policy> policies, Alert alert)
        {
            return policies.Where(p => p.Enabled && MatchesCriteria(alert, p))
                .OrderByDescending(p => (string.IsNullOrWhiteSpace(p.MatchAttackTypes) ? 0 : 2)
                    + (p.MatchProtocol == 0 ? 0 : 1))
                .ThenBy(p => p.CreatedAt).ThenBy(p => p.Id)
                .FirstOrDefault();
        }

        public Alert Evaluate(Alert alert, Policy? policy)
        {
            var now = _timeProvider.GetLocalNow().DateTime;
            if (alert.Source == DetectionSource.None || alert.AttackType == AttackTypes.Benign)
                return CreateDecision(alert, PolicyAction.Monitor, "benign", now);

            if (policy == null)
                return CreateDecision(alert, PolicyAction.Monitor, "no_match", now);
            if (!policy.Enabled)
                return CreateDecision(alert, PolicyAction.Monitor, "policy_disabled", now);
            if (!MatchesCriteria(alert, policy))
                return CreateDecision(alert, PolicyAction.Monitor, "no_match", now);

            // 页面阈值用于决策，不改变模型的检测阈值。
            // Page thresholds affect decisions, not model detection thresholds.
            if (alert.Source != DetectionSource.PreFilter)
            {
                var threshold = alert.Source == DetectionSource.RandomForest
                    ? policy.RfConfidenceThreshold : policy.IfConfidenceThreshold;
                if (threshold == null)
                    return CreateDecision(alert, PolicyAction.Monitor, "threshold_disabled", now);
                if (!float.IsFinite(alert.Confidence) || !float.IsFinite(threshold.Value)
                    || threshold < 0 || threshold > 1 || alert.Confidence < threshold)
                    return CreateDecision(alert, PolicyAction.Monitor, "below_threshold", now);
            }

            // 未知异常只告警，不自动封禁。
            // Unknown anomalies are Monitor-only.
            if (alert.AttackType == AttackTypes.UnknownAnomaly || alert.Source == DetectionSource.IsolationForest)
                return CreateDecision(alert, PolicyAction.Monitor, "unknown_anomaly_monitor_only", now);

            if (AddressAllowlist.Contains(alert.SourceIp, _allowlist))
                return CreateDecision(alert, PolicyAction.Monitor, "allowlisted_source", now);
            if (policy.BlockDurationMinutes <= 0)
                return CreateDecision(alert, PolicyAction.Monitor, "invalid_block_duration", now);

            // 自动封禁必须限定源地址，避免通配规则绕过白名单。
            // Automatic blocks must constrain the source IP to preserve the allowlist.
            if (policy.RuleSourceIpAction != PolicyAction.Block)
                return CreateDecision(alert, PolicyAction.Monitor, "source_ip_not_restricted", now);

            return CreateDecision(alert, PolicyAction.Block, "attack_detected", now);
        }

        private static bool MatchesCriteria(Alert alert, Policy policy)
        {
            if (policy.DetectionSource != alert.Source)
                return false;

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

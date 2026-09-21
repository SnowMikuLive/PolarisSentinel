using System.Net;
using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.PolicyDecision
{
    // Maps a detection onto Allow / Monitor / Block using the owner's policy thresholds.
    public class PolicyEngine : IPolicyEngine
    {
        private readonly TimeProvider _timeProvider;
        private readonly ILogger<PolicyEngine> _logger;
        private readonly object _lock = new object();
        private readonly Dictionary<string, DateTime> _lastBlockTimes = new Dictionary<string, DateTime>();
        private string[] _allowlistEntries = Array.Empty<string>();
        private AddressAllowlist? _allowlist;
        private int _alertCounter;

        public PolicyEngine(TimeProvider timeProvider, ILogger<PolicyEngine> logger)
        {
            _timeProvider = timeProvider;
            _logger = logger;
        }

        // Evaluates a detection and writes the decision back onto the alert.
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

            // Evaluate serially to avoid concurrent duplicate Blocks per IP.
            lock (_lock)
            {
                var now = _timeProvider.GetLocalNow().DateTime;
                var cooldown = TimeSpan.FromSeconds(Math.Max(0, policy.DecisionCooldownSeconds));
                RemoveExpiredCooldowns(now, cooldown);

                // Benign traffic is never acted on.
                if (alert.Source == DetectionSource.None || alert.AttackType == AttackTypes.Benign)
                {
                    return CreateDecision(alert, policy, PolicyAction.Monitor, "benign", now);
                }

                // The alert must match the policy's attack type + protocol criteria.
                if (!MatchesCriteria(alert, policy))
                {
                    return CreateDecision(alert, policy, PolicyAction.Monitor, "no_match", now);
                }

                // Pre-filter verdicts are rule-based and carry confidence 1, so they always pass.
                float? threshold = alert.Source switch
                {
                    DetectionSource.RandomForest => policy.RfConfidenceThreshold,
                    DetectionSource.IsolationForest => policy.IfConfidenceThreshold,
                    DetectionSource.PreFilter => 1f,
                    _ => null
                };

                // Confidence below the threshold: keep monitoring.
                if (threshold is null || alert.Confidence < threshold)
                {
                    return CreateDecision(alert, policy, PolicyAction.Monitor, "confidence_below_threshold", now);
                }

                // Allowlisted addresses are never blocked.
                if (GetAllowlist(policy).Contains(alert.SourceIp))
                {
                    return CreateDecision(alert, policy, PolicyAction.Monitor, "allowlisted", now);
                }

                // Same address already blocked within the cooldown window.
                if (!TryRecordBlock(alert.SourceIp, cooldown, now))
                {
                    return CreateDecision(alert, policy, PolicyAction.Monitor, "cooldown", now);
                }

                return CreateDecision(alert, policy, PolicyAction.Block, "confidence_threshold_met", now);
            }
        }

        // Seed the alert counter from the highest existing alert number.
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

        private void RemoveExpiredCooldowns(DateTime now, TimeSpan cooldown)
        {
            var expired = _lastBlockTimes.Where(e => now - e.Value >= cooldown).Select(e => e.Key).ToList();
            foreach (string ip in expired)
            {
                _lastBlockTimes.Remove(ip);
            }
        }

        private bool TryRecordBlock(string sourceIp, TimeSpan cooldown, DateTime now)
        {
            if (cooldown <= TimeSpan.Zero)
            {
                return true;
            }

            string key = sourceIp ?? string.Empty;
            if (IPAddress.TryParse(sourceIp, out var address))
            {
                if (address.IsIPv4MappedToIPv6)
                {
                    address = address.MapToIPv4();
                }
                key = address.ToString();
            }

            if (_lastBlockTimes.TryGetValue(key, out var lastBlock) && now - lastBlock < cooldown)
            {
                return false;
            }

            _lastBlockTimes[key] = now;
            return true;
        }

        // An alert must match every configured criterion; an empty/zero criterion means Any.
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

        // Empty configured list = any attack type.
        private static bool MatchesAttackType(string? attackType, string? configured)
        {
            if (string.IsNullOrWhiteSpace(configured))
            {
                return true;
            }

            var entries = configured.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            return entries.Any(e => string.Equals(e, attackType, StringComparison.OrdinalIgnoreCase));
        }

        private AddressAllowlist GetAllowlist(Policy policy)
        {            var entries = string.IsNullOrWhiteSpace(policy.Allowlist)
                ? Array.Empty<string>()
                : policy.Allowlist.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (_allowlist == null || !entries.SequenceEqual(_allowlistEntries))
            {
                _allowlistEntries = entries.ToArray();
                _allowlist = new AddressAllowlist(_allowlistEntries, _logger);
            }
            return _allowlist;
        }

        // Write the decision onto the alert and return it.
        private Alert CreateDecision(Alert alert, Policy policy, PolicyAction action, string reason, DateTime now)
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

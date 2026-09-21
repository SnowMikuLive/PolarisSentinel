using System.Net;
using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using Decision = PolarisSentinel.Core.Models.Policy;

namespace PolarisSentinel.PolicyDecision
{
    //推理结果→ Ignore / Monitor / Block；Unknown仅Monitor
    //Maps detections to Ignore / Monitor / Block; unknown anomalies Monitor-only
    public class PolicyEngine : IPolicyEngine
    {
        private readonly Func<Policy> _settingsProvider;
        private readonly TimeProvider _timeProvider;
        private readonly ILogger<PolicyEngine> _logger;
        private readonly object _lock = new object();
        private readonly Dictionary<string, DateTimeOffset> _lastBlockTimes = new Dictionary<string, DateTimeOffset>();
        private string[] _allowlistEntries = Array.Empty<string>();
        private AddressAllowlist? _allowlist;

        //全局告警计数器（RF / IF共用）
        //Global alert counter shared by RF and IF
        private int _alertCounter;

        public PolicyEngine(Func<Policy> settingsProvider, TimeProvider timeProvider, ILogger<PolicyEngine> logger)
        {
            _settingsProvider = settingsProvider ?? throw new ArgumentNullException(nameof(settingsProvider));
            _timeProvider = timeProvider;
            _logger = logger;
        }

        public Decision Evaluate(Alert result)
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            //串行评估，避免同IP并发重复Block
            //Evaluate serially to avoid concurrent duplicate Blocks per IP
            lock (_lock)
            {
                var settings = _settingsProvider();
                var cooldown = TimeSpan.FromSeconds(Math.Max(0, settings.DecisionCooldownSeconds));
                RemoveExpiredCooldowns(_timeProvider.GetUtcNow(), cooldown);

                if (result.Source == DetectionSource.None || result.AttackType == AttackTypes.Benign)
                {
                    return CreateDecision(result, PolicyAction.Ignore, "benign_or_no_detection");
                }

                if (!float.IsFinite(result.Confidence) || result.Confidence < 0 || result.Confidence > 1)
                {
                    _logger.LogWarning("Ignoring invalid confidence {Confidence} from {SourceIp}",
                        result.Confidence, result.SourceIp);
                    return CreateDecision(result, PolicyAction.Ignore, "invalid_confidence");
                }

                //阈值使用与置信度相同的float精度。
                //Use the same float precision as the confidence value.
                float alertThreshold = (float)settings.RfConfidenceThreshold;
                float blockThreshold = (float)settings.AutoBlockConfidenceThreshold;

                //未知异常只告警，不自动封禁。
                //Unknown anomalies only raise alerts,never automatic blocks.
                if (result.AttackType == AttackTypes.UnknownAnomaly)
                {
                    if (result.Confidence >= alertThreshold)
                    {
                        return CreateDecision(result, PolicyAction.Monitor, "unknown_anomaly_monitor_only");
                    }
                    return CreateDecision(result, PolicyAction.Ignore, "confidence_below_alert_threshold");
                }

                if (result.Source != DetectionSource.RandomForest)
                {
                    return CreateDecision(result, PolicyAction.Ignore, "unsupported_detection_source");
                }

                if (result.Confidence < alertThreshold)
                {
                    return CreateDecision(result, PolicyAction.Ignore, "confidence_below_alert_threshold");
                }

                if (result.Confidence < blockThreshold)
                {
                    return CreateDecision(result, PolicyAction.Monitor, "rf_monitor_confidence");
                }

                if (GetAllowlist(settings).Contains(result.SourceIp))
                {
                    return CreateDecision(result, PolicyAction.Monitor, "allowlist: Block downgraded to Monitor");
                }

                if (!TryRecordBlock(result.SourceIp, cooldown))
                {
                    return CreateDecision(result, PolicyAction.Ignore, "cooldown");
                }

                return CreateDecision(result, PolicyAction.Block, "rf_block_confidence");
            }
        }

        private void RemoveExpiredCooldowns(DateTimeOffset now, TimeSpan cooldown)
        {
            var expiredIps = new List<string>();
            foreach (var entry in _lastBlockTimes)
            {
                if (now - entry.Value >= cooldown)
                {
                    expiredIps.Add(entry.Key);
                }
            }

            foreach (string ip in expiredIps)
            {
                _lastBlockTimes.Remove(ip);
            }
        }

        private bool TryRecordBlock(string sourceIp, TimeSpan cooldown)
        {
            if (cooldown <= TimeSpan.Zero)
            {
                return true;
            }

            //同一IP的不同写法使用同一个冷却记录。
            //Different forms of the same IP use one cooldown record.
            string key = sourceIp ?? string.Empty;
            if (IPAddress.TryParse(sourceIp, out var address))
            {
                if (address.IsIPv4MappedToIPv6)
                {
                    address = address.MapToIPv4();
                }
                key = address.ToString();
            }

            var now = _timeProvider.GetUtcNow();
            if (_lastBlockTimes.TryGetValue(key, out var lastBlock) && now - lastBlock < cooldown)
            {
                return false;
            }

            _lastBlockTimes[key] = now;
            return true;
        }

        public Task RefreshSettingsAsync()
        {
            lock (_lock)
            {
                GetAllowlist(_settingsProvider());
            }
            _logger.LogInformation("Policy settings refreshed");
            return Task.CompletedTask;
        }

        private AddressAllowlist GetAllowlist(Policy settings)
        {
            var entries = settings.Allowlist ?? Array.Empty<string>();
            if (_allowlist == null || !entries.SequenceEqual(_allowlistEntries))
            {
                _allowlistEntries = entries.ToArray();
                _allowlist = new AddressAllowlist(_allowlistEntries, _logger);
            }
            return _allowlist;
        }

        private Decision CreateDecision(Alert result, PolicyAction action, string reason)
        {
            var decision = new Decision
            {
                Id = string.Empty,
                Name = string.Empty,
                AlertId = EntityIds.Alert(result.Source, ++_alertCounter),
                Action = action,
                SourceIp = result.SourceIp,
                AttackType = result.AttackType,
                Confidence = result.Confidence,
                DetectionSource = result.Source,
                DecidedAt = _timeProvider.GetUtcNow().UtcDateTime,
                Reason = reason
            };

            _logger.LogDebug(
                "Policy decision {AlertId}: {Action} for {SourceIp}, attack {AttackType}, confidence {Confidence}, reason {Reason}",
                decision.AlertId, decision.Action, decision.SourceIp,
                decision.AttackType, decision.Confidence, decision.Reason);

            return decision;
        }
    }
}

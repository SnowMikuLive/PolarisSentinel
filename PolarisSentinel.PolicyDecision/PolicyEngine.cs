using System.Net;
using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.PolicyDecision
{
    // 推理结果 → Ignore / Monitor / Block；Unknown 仅 Monitor
    // Maps detections to Ignore / Monitor / Block; unknown anomalies Monitor-only
    public class PolicyEngine : IPolicyEngine
    {
        private readonly Func<UserSettings> _settingsProvider;
        private readonly TimeProvider _timeProvider;
        private readonly ILogger<PolicyEngine> _logger;
        private readonly object _lock = new object();
        private readonly Dictionary<string, DateTimeOffset> _lastBlockTimes = new Dictionary<string, DateTimeOffset>();
        private string[] _allowlistEntries = Array.Empty<string>();
        private AddressAllowlist? _allowlist;

        // 全局告警计数器（RF / IF 共用）
        // Global alert counter shared by RF and IF
        private int _alertCounter;

        public PolicyEngine(Func<UserSettings> settingsProvider, TimeProvider timeProvider, ILogger<PolicyEngine> logger)
        {
            _settingsProvider = settingsProvider ?? throw new ArgumentNullException(nameof(settingsProvider));
            _timeProvider = timeProvider;
            _logger = logger;
        }

        public Alert Evaluate(Alert result)
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            // 串行评估，避免同 IP 并发重复 Block
            // Evaluate serially to avoid concurrent duplicate Blocks per IP
            lock (_lock)
            {
                var settings = _settingsProvider();
                var cooldown = TimeSpan.FromSeconds(Math.Max(0, settings.DecisionCooldownSeconds));
                RemoveExpiredCooldowns(_timeProvider.GetUtcNow(), cooldown);

                if (result.Source == DetectionSource.None || result.AttackType == AttackTypes.Benign)
                {
                    return CreateDecision(result, PolicyAction.Ignore, "benign_or_no_detection");
                }

                // Rule-based pre-filter verdicts are trusted: block without a confidence check.
                if (result.Source == DetectionSource.PreFilter)
                {
                    if (GetAllowlist(settings).Contains(result.SourceIp))
                    {
                        return CreateDecision(result, PolicyAction.Monitor, "allowlist: Block downgraded to Monitor");
                    }

                    if (!TryRecordBlock(result.SourceIp, cooldown))
                    {
                        return CreateDecision(result, PolicyAction.Ignore, "cooldown");
                    }

                    return CreateDecision(result, PolicyAction.Block, "prefilter_block");
                }

                if (!float.IsFinite(result.Confidence) || result.Confidence < 0 || result.Confidence > 1)
                {
                    _logger.LogWarning("Ignoring invalid confidence {Confidence} from {SourceIp}",
                        result.Confidence, result.SourceIp);
                    return CreateDecision(result, PolicyAction.Ignore, "invalid_confidence");
                }

                // 阈值使用与置信度相同的 float 精度。
                // Use the same float precision as the confidence value.
                float alertThreshold = (float)settings.RfConfidenceThreshold;
                float blockThreshold = (float)settings.AutoBlockConfidenceThreshold;

                // 未知异常只告警，不自动封禁。
                // Unknown anomalies only raise alerts, never automatic blocks.
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

            // 同一 IP 的不同写法使用同一个冷却记录。
            // Different forms of the same IP use one cooldown record.
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

        // 用已有告警的最大编号初始化计数器
        // Seed the alert counter from the highest existing alert number
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

        private AddressAllowlist GetAllowlist(UserSettings settings)
        {
            var entries = string.IsNullOrWhiteSpace(settings.Allowlist)
                ? Array.Empty<string>()
                : settings.Allowlist.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (_allowlist == null || !entries.SequenceEqual(_allowlistEntries))
            {
                _allowlistEntries = entries.ToArray();
                _allowlist = new AddressAllowlist(_allowlistEntries, _logger);
            }
            return _allowlist;
        }

        // 将决策写回告警并返回
        // Write the decision onto the alert and return it
        private Alert CreateDecision(Alert result, PolicyAction action, string reason)
        {
            result.Id = EntityIds.Alert(result.Source, ++_alertCounter);
            result.Action = action;
            result.DecidedAt = _timeProvider.GetUtcNow().UtcDateTime;
            result.Reason = reason;

            _logger.LogDebug(
                "Policy decision {AlertId}: {Action} for {SourceIp}, attack {AttackType}, confidence {Confidence}, reason {Reason}",
                result.Id, result.Action, result.SourceIp,
                result.AttackType, result.Confidence, result.Reason);

            return result;
        }
    }
}

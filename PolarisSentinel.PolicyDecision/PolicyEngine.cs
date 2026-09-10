using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using Decision = PolarisSentinel.Core.Models.PolicyDecision;

namespace PolarisSentinel.PolicyDecision;

// 将推理结果映射为 Ignore / Monitor / Block 三种策略动作（US010）。
// Maps inference results to Ignore / Monitor / Block policy actions (US010).
//
// 决策规则摘要:
// - 良性或无检测 → Ignore
// - Unknown_Anomaly（IF）→ 仅 Monitor，永不 Block
// - RF 已知攻击 + 置信度 ≥ 告警阈值 → Monitor
// - RF 已知攻击 + 置信度 ≥ 封禁阈值 + 非白名单 → Block
// Decision rules:
// - Benign or no detection → Ignore
// - Unknown_Anomaly (IF) → Monitor only, never Block
// - RF known attack + confidence ≥ alert threshold → Monitor
// - RF known attack + confidence ≥ block threshold + not allowlisted → Block
public sealed class PolicyEngine : IPolicyEngine
{
    private readonly IOptionsMonitor<PolicySettings> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<PolicyEngine> _logger;
    private readonly object _allowlistLock = new();
    private string[] _allowlistEntries = [];
    private AddressAllowlist? _allowlist;

    public PolicyEngine(
        IOptionsMonitor<PolicySettings> options,
        TimeProvider timeProvider,
        ILogger<PolicyEngine> logger)
    {
        _options = options;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    public Decision Evaluate(DetectionResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        if (result.Source == DetectionSource.None || result.AttackType == AttackTypes.Benign)
            return CreateDecision(result, PolicyAction.Ignore, "benign_or_no_detection");

        if (!float.IsFinite(result.Confidence) || result.Confidence < 0 || result.Confidence > 1)
        {
            _logger.LogWarning("Ignoring invalid confidence {Confidence} from {SourceIp}",
                result.Confidence, result.SourceIp);
            return CreateDecision(result, PolicyAction.Ignore, "invalid_confidence");
        }

        // 每次决策读取 CurrentValue，配置热重载后下一条流即生效
        // Read CurrentValue per decision so configuration reloads affect the next flow
        var settings = _options.CurrentValue;
        // 与模型 float 精度对齐，使 0.70f 能满足 0.7 阈值
        // Match the model's float precision so values such as 0.70f meet a 0.7 threshold
        var alertThreshold = (float)settings.RfConfidenceThreshold;
        var blockThreshold = (float)settings.AutoBlockConfidenceThreshold;

        if (result.AttackType == AttackTypes.UnknownAnomaly)
        {
            // 未知异常仅触发 Monitor，不自动封禁（仪表盘噪声，非阻断动作）
            // Unknown anomalies only raise Monitor alerts, never auto-block
            return result.Confidence >= alertThreshold
                ? CreateDecision(result, PolicyAction.Monitor, "unknown_anomaly_monitor_only")
                : CreateDecision(result, PolicyAction.Ignore, "confidence_below_alert_threshold");
        }

        // 只有 RF 分类结果才允许 Block
        // Only an RF classification can authorize the Block action
        if (result.Source != DetectionSource.RandomForest)
            return CreateDecision(result, PolicyAction.Ignore, "unsupported_detection_source");

        if (result.Confidence < alertThreshold)
            return CreateDecision(result, PolicyAction.Ignore, "confidence_below_alert_threshold");

        if (result.Confidence < blockThreshold)
            return CreateDecision(result, PolicyAction.Monitor, "rf_monitor_confidence");

        if (GetAllowlist(settings).Contains(result.SourceIp))
            return CreateDecision(result, PolicyAction.Monitor, "allowlist: Block downgraded to Monitor");

        return CreateDecision(result, PolicyAction.Block, "rf_block_confidence");
    }

    public Task RefreshSettingsAsync()
    {
        // IOptionsMonitor 负责配置重载；此处刷新派生的 CIDR 缓存
        // IOptionsMonitor handles provider reloads; refresh the derived CIDR cache here
        GetAllowlist(_options.CurrentValue);
        _logger.LogInformation("Policy settings refreshed from the current options");
        return Task.CompletedTask;
    }

    private AddressAllowlist GetAllowlist(PolicySettings settings)
    {
        lock (_allowlistLock)
        {
            var entries = settings.Allowlist ?? [];
            if (_allowlist is null || !entries.SequenceEqual(_allowlistEntries))
            {
                _allowlistEntries = entries.ToArray();
                _allowlist = new AddressAllowlist(_allowlistEntries, _logger);
            }
            return _allowlist;
        }
    }

    private Decision CreateDecision(DetectionResult result, PolicyAction action, string reason)
    {
        var decision = new Decision
        {
            AlertId = Guid.NewGuid(),
            Action = action,
            SourceIp = result.SourceIp,
            AttackType = result.AttackType,
            Confidence = result.Confidence,
            DecidedAt = _timeProvider.GetUtcNow().UtcDateTime,
            Reason = reason,
        };

        _logger.LogDebug(
            "Policy decision {AlertId}: {Action} for {SourceIp}, attack {AttackType}, confidence {Confidence}, reason {Reason}",
            decision.AlertId, decision.Action, decision.SourceIp,
            decision.AttackType, decision.Confidence, decision.Reason);

        return decision;
    }
}

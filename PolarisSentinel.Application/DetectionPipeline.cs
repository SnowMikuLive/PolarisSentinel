using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Application;

<<<<<<< HEAD
//检测用例编排：推理→策略→防火墙执行
//Orchestrates inference,policy decision,and firewall enforcement
=======
// Application use case: pre-filter verdict -> inference -> policy -> firewall enforcement.
>>>>>>> d47e7ec0c32803f010bc8a3c97a4dc42d392cd92
public class DetectionPipeline : IDetectionPipeline
{
    private readonly IInferenceEngine _inference;
    private readonly IPolicyEngine _policy;
    private readonly IFirewallEnforcer _firewall;
    private readonly int _blockDurationMinutes;
    private readonly ILogger<DetectionPipeline> _logger;

    public DetectionPipeline(
        IInferenceEngine inference,
        IPolicyEngine policy,
        IFirewallEnforcer firewall,
        int blockDurationMinutes,
        ILogger<DetectionPipeline> logger)
    {
        _inference = inference;
        _policy = policy;
        _firewall = firewall;
        _blockDurationMinutes = blockDurationMinutes;
        _logger = logger;
    }

    // Runs one flow through detection, policy evaluation and enforcement.
    public Alert ProcessFlow(FlowFeatureVector flow)
    {
        var detection = _inference.Detect(flow);
        var decision = _policy.Evaluate(detection);

        if (decision.Action == PolicyAction.Block)
        {
            var duration = TimeSpan.FromMinutes(_blockDurationMinutes);
            _firewall.BlockIp(decision, duration);
<<<<<<< HEAD
            //同一IP可能复用已有规则
            //The same IP may reuse an existing rule
=======
            // The same IP may reuse an existing rule.
>>>>>>> d47e7ec0c32803f010bc8a3c97a4dc42d392cd92
            decision.RuleName = _firewall.GetAllRules().FirstOrDefault(rule =>
                rule.RemoteAddress == decision.SourceIp && rule.Enabled &&
                rule.ExpiresAt > new DateTimeOffset(decision.DecidedAt))?.Name;
            _logger.LogInformation(
                "Block requested for {SourceIp}, {Minutes} minutes (attack {AttackType})",
                decision.SourceIp, _blockDurationMinutes, decision.AttackType);
        }

        return decision;
    }

    // Builds a detection result straight from a rule-based pre-filter verdict.
    public static Alert FromPreFilterVerdict(FlowFeatureVector flow, PreFilterResult verdict)
    {
        return new Alert
        {
            SourceIp = flow.SourceIp,
            SourcePort = flow.SourcePort,
            DestinationIp = flow.DestinationIp,
            DestinationPort = flow.DestinationPort,
            Protocol = flow.Protocol,
            AttackType = verdict.AttackType,
            Confidence = verdict.Confidence,
            Source = DetectionSource.PreFilter,
            DetectedAt = flow.FlowEndTime,
            Reason = verdict.Reason
        };
    }

    // Pre-filter attacks are treated exactly like a model detection, so no confidence is needed.
    public static bool IsPreFilterAttack(FlowFeatureVector flow) => flow.PreFilterVerdict is not null;
}

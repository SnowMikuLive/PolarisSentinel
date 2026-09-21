using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Application;

//检测用例编排：推理→策略→防火墙执行
//Orchestrates inference,policy decision,and firewall enforcement
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

    public Policy ProcessFlow(FlowFeatureVector flow)
    {
        var detection = _inference.Detect(flow);
        var decision = _policy.Evaluate(detection);

        if (decision.Action == PolicyAction.Block)
        {
            var duration = TimeSpan.FromMinutes(_blockDurationMinutes);
            _firewall.BlockIp(decision, duration);
            //同一IP可能复用已有规则
            //The same IP may reuse an existing rule
            decision.RuleName = _firewall.GetAllRules().FirstOrDefault(rule =>
                rule.RemoteAddress == decision.SourceIp && rule.Enabled && rule.IsBlockRule &&
                rule.ExpiresAt > new DateTimeOffset(decision.DecidedAt))?.Name;
            _logger.LogInformation(
                "Block requested for {SourceIp}, {Minutes} minutes (attack {AttackType})",
                decision.SourceIp, _blockDurationMinutes, decision.AttackType);
        }

        return decision;
    }
}

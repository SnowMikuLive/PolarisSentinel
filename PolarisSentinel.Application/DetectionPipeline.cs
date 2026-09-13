using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Application;

// Orchestrates the detection use case: inference -> policy decision -> enforcement.
// This is the application-layer use case; it depends only on domain contracts
// (IInferenceEngine, IPolicyEngine, IFirewallEnforcer) and knows nothing about
// the presentation or persistence layers.
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

    public PolicyDecision ProcessFlow(FlowFeatureVector flow)
    {
        // Step 1: run inference on the completed flow.
        var detection = _inference.Detect(flow);

        // Step 2: evaluate the policy against the detection.
        var decision = _policy.Evaluate(detection);

        // Step 3: enforce Block decisions by creating a firewall rule.
        if (decision.Action == PolicyAction.Block)
        {
            var duration = TimeSpan.FromMinutes(_blockDurationMinutes);
            _firewall.BlockIp(decision, duration);
            _logger.LogInformation(
                "Blocked {SourceIp} for {Minutes} minutes (attack {AttackType})",
                decision.SourceIp, _blockDurationMinutes, decision.AttackType);
        }

        return decision;
    }
}

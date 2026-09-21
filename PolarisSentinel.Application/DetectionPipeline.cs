using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Application;

// Orchestrates one flow: capture verdict -> AI inference -> policy decision -> firewall rule.
public class DetectionPipeline : IDetectionPipeline
{
    private readonly IInferenceEngine _inference;
    private readonly IPolicyEngine _policy;
    private readonly IFirewallEnforcer _firewall;
    private readonly ILogger<DetectionPipeline> _logger;

    public DetectionPipeline(
        IInferenceEngine inference,
        IPolicyEngine policy,
        IFirewallEnforcer firewall,
        ILogger<DetectionPipeline> logger)
    {
        _inference = inference;
        _policy = policy;
        _firewall = firewall;
        _logger = logger;
    }

    // Runs one flow through detection, policy evaluation and enforcement.
    public Alert ProcessFlow(FlowFeatureVector flow, Policy policy)
    {
        // A rule-based pre-filter verdict is already an attack: skip inference entirely.
        var detection = flow.PreFilterVerdict is { } verdict
            ? BuildPreFilterAlert(flow, verdict)
            : _inference.Detect(flow);

        var decision = _policy.Evaluate(detection, policy);

        if (decision.Action == PolicyAction.Block)
        {
            // The policy decides which parts of the 5-tuple the rule constrains;
            // a field whose action is Allow becomes Any (a wildcard) in the rule.
            var scope = FirewallRuleScope.FromPolicy(
                policy,
                decision.SourceIp,
                decision.SourcePort,
                decision.DestinationIp,
                decision.DestinationPort,
                decision.Protocol);

            var rule = _firewall.Block(
                decision.SourceIp,
                decision.SourcePort,
                decision.DestinationIp,
                decision.DestinationPort,
                decision.Protocol,
                decision.Action,
                decision.Id,
                decision.AttackType,
                TimeSpan.FromMinutes(policy.BlockDurationMinutes),
                scope);

            decision.RuleName = rule.Name;
            _logger.LogInformation(
                "Block requested for {SourceIp}, {Minutes} minutes (attack {AttackType}, all traffic {AllTraffic})",
                decision.SourceIp, policy.BlockDurationMinutes, decision.AttackType, scope.IsAny);
        }

        return decision;
    }

    // Builds an alert straight from a rule-based pre-filter verdict, reusing the flow's 5-tuple.
    private static Alert BuildPreFilterAlert(FlowFeatureVector flow, PreFilterResult verdict) => new()
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

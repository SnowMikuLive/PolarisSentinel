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
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<DetectionPipeline> _logger;

    public DetectionPipeline(
        IInferenceEngine inference,
        IPolicyEngine policy,
        IFirewallEnforcer firewall,
        IUnitOfWork unitOfWork,
        ILogger<DetectionPipeline> logger)
    {
        _inference = inference;
        _policy = policy;
        _firewall = firewall;
        _unitOfWork = unitOfWork;
        _logger = logger;
    }

    // Runs one flow through detection, policy evaluation and enforcement.
    public Alert ProcessFlow(FlowFeatureVector flow, Policy policy)
    {
        return ProcessFlow(flow, new[] { policy });
    }

    public Alert ProcessFlow(FlowFeatureVector flow, IReadOnlyList<Policy> policies)
    {
        // A rule-based pre-filter verdict is already an attack: skip inference entirely.
        var detection = flow.PreFilterVerdict is { } verdict
            ? BuildPreFilterAlert(flow, verdict)
            : _inference.Detect(flow);

        var policy = _policy.SelectPolicy(policies, detection);
        var decision = _policy.Evaluate(detection, policy);

        // The alert must be committed before any rule can reference it,
        // because Rule.AlertId is a foreign key into Alerts.
        _unitOfWork.Alerts.Add(decision);
        _unitOfWork.SaveChangesAsync().GetAwaiter().GetResult();

        if (decision.Action == PolicyAction.Block && policy != null)
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
                policy.Id,
                decision.AttackType,
                TimeSpan.FromMinutes(policy.BlockDurationMinutes),
                scope);

            decision.RuleName = rule.Name;

            // The rule is staged by the enforcer; commit it now that its alert exists.
            _unitOfWork.SaveChangesAsync().GetAwaiter().GetResult();

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

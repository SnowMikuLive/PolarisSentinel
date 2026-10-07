using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Application;

// Orchestrates one flow: pre-filter -> AI (when needed) -> policy -> firewall.
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

    public DetectionOutcome ProcessFlow(FlowFeatureVector flow, IReadOnlyList<Policy> policies)
    {
        var verdict = flow.PreFilterVerdict;

        // A known attack is alerted and blocked from the pre-filter verdict. The AI engine
        // still runs so its opinion is recorded on the alert (the heuristic verdict stays
        // authoritative for blocking).
        if (verdict is { IsKnownAttack: true })
        {
            var alert = BuildPreFilterAlert(flow, verdict);
            var modelOpinion = _inference.Detect(flow);
            if (modelOpinion.AttackType != AttackTypes.Benign)
            {
                alert.Description = $"{alert.Description} | Model: {modelOpinion.AttackType} ({modelOpinion.ConfidenceScore:0.00})";
            }
            return Evaluate(alert, policies);
        }

        if (verdict is not { IsSuspicious: true })
        {
            return new DetectionOutcome
            {
                Verdict = TrafficVerdict.Normal,
                SourceIp = flow.SourceIp,
                SourcePort = flow.SourcePort,
                DestinationIp = flow.DestinationIp,
                DestinationPort = flow.DestinationPort
            };
        }

        var detection = _inference.Detect(flow);
        if (detection.AttackType == AttackTypes.Benign)
        {
            return new DetectionOutcome
            {
                Verdict = TrafficVerdict.Normal,
                Description = "No attack detected.",
                SourceIp = flow.SourceIp,
                SourcePort = flow.SourcePort,
                DestinationIp = flow.DestinationIp,
                DestinationPort = flow.DestinationPort
            };
        }

        // The AI engine may flag an anomaly below the configured alert threshold.
        if (!MeetsAlertThreshold(detection, policies))
        {
            return new DetectionOutcome
            {
                Verdict = TrafficVerdict.Suspicious,
                Description = detection.Description ?? "Below the alert threshold.",
                SourceIp = flow.SourceIp,
                SourcePort = flow.SourcePort,
                DestinationIp = flow.DestinationIp,
                DestinationPort = flow.DestinationPort
            };
        }

        return Evaluate(detection, policies);
    }

    // Runs the alert through policy evaluation and, when blocked, firewall enforcement.
    private DetectionOutcome Evaluate(Alert alert, IReadOnlyList<Policy> policies)
    {
        // Only non-benign detections are alerted; a benign flow never reaches persistence.
        if (alert.AttackType == AttackTypes.Benign)
        {
            return new DetectionOutcome
            {
                Verdict = TrafficVerdict.Normal,
                Description = "No attack detected.",
                SourceIp = alert.SourceIp,
                SourcePort = alert.SourcePort,
                DestinationIp = alert.DestinationIp,
                DestinationPort = alert.DestinationPort
            };
        }

        // The alert id is assigned here so the firewall rule name can key off it.
        if (string.IsNullOrEmpty(alert.Id))
        {
            alert.Id = _unitOfWork.Alerts.NextIdAsync().GetAwaiter().GetResult();
        }

        var decision = _policy.Evaluate(alert, policies);

        _unitOfWork.Alerts.Add(alert);
        _unitOfWork.SaveChangesAsync().GetAwaiter().GetResult();

        Rule? rule = null;
        if (PolicyActions.IsBlocking(decision.Action))
        {
            rule = _firewall.Apply(
                decision,
                decision.PolicyId,
                alert.Id,
                alert.AttackType,
                TimeSpan.FromMinutes(decision.BlockDurationMinutes));

            // The rule is staged by the enforcer; commit it now that its alert exists.
            _unitOfWork.SaveChangesAsync().GetAwaiter().GetResult();

            _logger.LogInformation(
                "Block requested for {SourceIp}, {Minutes} minutes (attack {AttackType})",
                alert.SourceIp, decision.BlockDurationMinutes, alert.AttackType);
        }

        return new DetectionOutcome
        {
            Verdict = TrafficVerdict.Malicious,
            Description = alert.Description ?? decision.Reason,
            Alert = alert,
            Decision = decision,
            Rule = rule,
            SourceIp = alert.SourceIp,
            SourcePort = alert.SourcePort,
            DestinationIp = alert.DestinationIp,
            DestinationPort = alert.DestinationPort
        };
    }

    // An AI alert only counts when it reaches the threshold of a policy that could act on it.
    private static bool MeetsAlertThreshold(Alert alert, IReadOnlyList<Policy> policies)
    {
        return policies
            .Where(p => p.IsEnabled)
            .Where(p => p.DetectionSource is not { } source || source == alert.DetectionSource)
            .Any(p => p.MeetsThreshold(alert));
    }

    private static Alert BuildPreFilterAlert(FlowFeatureVector flow, PreFilterResult verdict)
    {
        // A spoofed/random-source flood cannot be stopped by blocking the (fake) source, so
        // the endpoints are swapped: the alert's source becomes the flooded destination, and
        // the inbound-IP policy then blocks traffic to the victim instead of a random IP.
        string sourceIp = verdict.IsSpoofedSource ? flow.DestinationIp : flow.SourceIp;
        string destinationIp = verdict.IsSpoofedSource ? flow.SourceIp : flow.DestinationIp;

        return new Alert
        {
            DetectionSource = DetectionSource.HeuristicBased,
            AttackType = verdict.AttackType!,
            ConfidenceScore = null,
            Description = verdict.Description,
            SourceIp = sourceIp,
            SourcePort = flow.SourcePort,
            DestinationIp = destinationIp,
            DestinationPort = flow.DestinationPort,
            Protocol = flow.Protocol,
            SynCount = flow.SynCount,
            AckCount = flow.AckCount,
            FinCount = flow.FinCount,
            RstCount = flow.RstCount,
            PshCount = flow.PshCount,
            FlowSnapshotJson = FlowSnapshot.Create(flow),
            BehaviorSnapshotJson = verdict.Aggregate is { } aggregate ? BehaviorSnapshot.Create(aggregate) : null,
            CreatedAt = flow.FlowEndTime
        };
    }
}

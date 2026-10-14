using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Core.Services;

namespace PolarisSentinel.Application;

// Orchestrates one flow: pre-filter -> AI (when needed) -> policy -> firewall.
public class DetectionPipeline : IDetectionPipeline
{
    private readonly IInferenceEngine _inference;
    private readonly IPolicyEngine _policy;
    private readonly IFirewallEnforcer _firewall;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<DetectionPipeline> _logger;
    private readonly DetectionRuntimeState? _detection;
    private readonly BlockedTrafficState? _blocked;

    private static readonly object _persistLock = new();

    public DetectionPipeline(
        IInferenceEngine inference,
        IPolicyEngine policy,
        IFirewallEnforcer firewall,
        IUnitOfWork unitOfWork,
        ILogger<DetectionPipeline> logger,
        DetectionRuntimeState? detection = null,
        BlockedTrafficState? blocked = null)
    {
        _inference = inference;
        _policy = policy;
        _firewall = firewall;
        _unitOfWork = unitOfWork;
        _logger = logger;
        _detection = detection;
        _blocked = blocked;
    }

    public DetectionOutcome ProcessFlow(FlowFeatureVector flow, IReadOnlyList<Policy> policies)
    {
        var verdict = flow.PreFilterVerdict;

        bool heuristic = _detection?.HeuristicEnabled ?? true;

        if (!flow.IsInbound)
        {
            return new DetectionOutcome
            {
                Verdict = TrafficVerdict.Normal,
                Description = "Outbound flow; not evaluated as an inbound attack.",
                SourceIp = flow.SourceIp,
                SourcePort = flow.SourcePort,
                DestinationIp = flow.DestinationIp,
                DestinationPort = flow.DestinationPort
            };
        }

        if (verdict is not { IsKnownAttack: true } && _blocked?.IsBlocked(flow.SourceIp) == true)
        {
            return new DetectionOutcome
            {
                Verdict = TrafficVerdict.Blocked,
                Description = "Blocked by an active rule; dropped by the firewall.",
                SourceIp = flow.SourceIp,
                SourcePort = flow.SourcePort,
                DestinationIp = flow.DestinationIp,
                DestinationPort = flow.DestinationPort
            };
        }

        if (heuristic && verdict is { IsKnownAttack: true })
        {
            var alert = BuildPreFilterAlert(flow, verdict);

            try
            {
                var modelOpinion = _inference.Detect(flow);
                if (modelOpinion.AttackType != AttackTypes.Benign)
                {
                    alert.Description = $"{alert.Description} | Model: {modelOpinion.AttackType} ({modelOpinion.ConfidenceScore:0.00})";
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Model opinion failed for a known attack; enforcing the heuristic verdict.");
            }

            return Evaluate(alert, policies, malicious: true);
        }

        if (heuristic && verdict is not { IsSuspicious: true })
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
                Verdict = TrafficVerdict.Suspicious,
                Description = $"{verdict?.Description} | Model: Benign",
                SourceIp = flow.SourceIp,
                SourcePort = flow.SourcePort,
                DestinationIp = flow.DestinationIp,
                DestinationPort = flow.DestinationPort
            };
        }

        // Isolation Forest anomalies are surfaced as alerts for review even below the policy
        // threshold: an unnamed anomaly is suspicious rather than a confirmed attack, but it
        // must still reach the Alerts list.
        bool isIsolationForestAnomaly = detection.AttackType == AttackTypes.UnknownAnomaly;

        if (!isIsolationForestAnomaly && !MeetsAlertThreshold(detection, policies))
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

        return Evaluate(detection, policies, malicious: AttackTypes.IsMalicious(detection.AttackType));
    }

    private DetectionOutcome Evaluate(Alert alert, IReadOnlyList<Policy> policies, bool malicious)
    {
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

        Rule? rule = null;

        lock (_persistLock)
        {
            if (string.IsNullOrEmpty(alert.Id))
            {
                alert.Id = _unitOfWork.Alerts.NextIdAsync().GetAwaiter().GetResult();
            }

            var decision = _policy.Evaluate(alert, policies);

            _unitOfWork.Alerts.Add(alert);
            _unitOfWork.SaveChangesAsync().GetAwaiter().GetResult();

            if (PolicyActions.IsBlocking(decision.Action))
            {
                try
                {
                    rule = _firewall.Apply(
                        decision,
                        decision.PolicyId,
                        alert.Id,
                        alert.AttackType,
                        TimeSpan.FromMinutes(decision.BlockDurationMinutes));

                    _unitOfWork.SaveChangesAsync().GetAwaiter().GetResult();

                    _logger.LogInformation(
                        "Block requested for {SourceIp}, {Minutes} minutes (attack {AttackType})",
                        alert.SourceIp, decision.BlockDurationMinutes, alert.AttackType);

                    if (rule.BlocksAddress)
                    {
                        _blocked?.Add(rule.BlockedIp);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(
                        ex, "Failed to enforce the block for alert {AlertId} ({AttackType} from {SourceIp})",
                        alert.Id, alert.AttackType, alert.SourceIp);
                }
            }

            return new DetectionOutcome
            {
                Verdict = malicious ? TrafficVerdict.Malicious : TrafficVerdict.Suspicious,
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
    }

    private static bool MeetsAlertThreshold(Alert alert, IReadOnlyList<Policy> policies)
    {
        return policies
            .Where(p => p.IsEnabled)
            .Where(p => p.DetectionSource is not { } source || source == alert.DetectionSource)
            .Any(p => p.MeetsThreshold(alert));
    }

    private static Alert BuildPreFilterAlert(FlowFeatureVector flow, PreFilterResult verdict)
    {
        string sourceIp = verdict.IsSpoofedSource ? flow.DestinationIp : flow.SourceIp;
        string destinationIp = verdict.IsSpoofedSource ? flow.SourceIp : flow.DestinationIp;

        return new Alert
        {
            DetectionSource = DetectionSource.HeuristicBased,
            AttackType = verdict.AttackType!,
            ConfidenceScore = null,
            SpoofedSource = verdict.IsSpoofedSource,
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

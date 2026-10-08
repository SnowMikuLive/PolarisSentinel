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

    // Alert ids are allocated by scanning the table for the highest "A-n". Flows complete
    // concurrently (one DI scope each), so two detections in a burst can compute the same
    // id; the second insert then fails and that alert *and its block* are lost. Serialize
    // id-assignment through enforcement so a burst can never drop a detection or a defence.
    private static readonly object _persistLock = new();

    public DetectionPipeline(
        IInferenceEngine inference,
        IPolicyEngine policy,
        IFirewallEnforcer firewall,
        IUnitOfWork unitOfWork,
        ILogger<DetectionPipeline> logger,
        DetectionRuntimeState? detection = null)
    {
        _inference = inference;
        _policy = policy;
        _firewall = firewall;
        _unitOfWork = unitOfWork;
        _logger = logger;
        _detection = detection;
    }

    public DetectionOutcome ProcessFlow(FlowFeatureVector flow, IReadOnlyList<Policy> policies)
    {
        var verdict = flow.PreFilterVerdict;

        // Heuristic triage can be switched off from the dashboard; then nothing is filtered and
        // every flow is handed to the AI engine for a verdict.
        bool heuristic = _detection?.HeuristicEnabled ?? true;

        // Only inbound traffic (remote -> local) is treated as an attack. Outbound flows are
        // still captured and shown on the dashboard, but this system defends the host, so it
        // never raises an alert or blocks on traffic the host itself initiated.
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

        // A known attack is alerted and blocked from the pre-filter verdict. The AI engine
        // still runs so its opinion is recorded on the alert (the heuristic verdict stays
        // authoritative for blocking).
        if (heuristic && verdict is { IsKnownAttack: true })
        {
            var alert = BuildPreFilterAlert(flow, verdict);

            // The heuristic verdict already justifies the alert and the block; the model
            // opinion is only extra detail on the alert, so a model failure must never lose
            // the defence.
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

            // A heuristic known attack is a confirmed malicious flow regardless of the model.
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

        // Everything that reaches the AI engine is suspicious traffic; it only becomes
        // malicious when the inference result is a confirmed attack category.
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

        // The AI inference result decides the final verdict: only a confirmed attack
        // category (DoS / PortScan / BruteForce) is malicious; an unnamed anomaly is
        // suspicious and is monitored rather than treated as a confirmed attack.
        return Evaluate(detection, policies, malicious: AttackTypes.IsMalicious(detection.AttackType));
    }

    // Runs the alert through policy evaluation and, when blocked, firewall enforcement.
    // The malicious flag is supplied by the caller from the AI inference result, so the
    // pipeline never labels a flow malicious on the strength of reaching this stage alone.
    private DetectionOutcome Evaluate(Alert alert, IReadOnlyList<Policy> policies, bool malicious)
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

                    // The rule is staged by the enforcer; commit it now that its alert exists.
                    _unitOfWork.SaveChangesAsync().GetAwaiter().GetResult();

                    _logger.LogInformation(
                        "Block requested for {SourceIp}, {Minutes} minutes (attack {AttackType})",
                        alert.SourceIp, decision.BlockDurationMinutes, alert.AttackType);
                }
                catch (Exception ex)
                {
                    // The alert is already persisted. An enforcement failure (e.g. a policy
                    // whose action cannot be expressed for this flow) must not abort the
                    // pipeline or hide the detection; the absent rule name signals it.
                    _logger.LogError(
                        ex, "Failed to enforce the block for alert {AlertId} ({AttackType} from {SourceIp})",
                        alert.Id, alert.AttackType, alert.SourceIp);
                }
            }

            return new DetectionOutcome
            {
                // Only a confirmed attack is malicious; anything else that produced an alert
                // (e.g. an unnamed anomaly) stays suspicious.
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

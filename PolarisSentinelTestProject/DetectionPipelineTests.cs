using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Application;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Core.Services;
using PolarisSentinel.FirewallEnforement;
using PolarisSentinel.PolicyDecision;

namespace PolarisSentienlUnitTestProject;

// Core of the detection pipeline: pre-filter verdict -> AI (when needed) -> policy -> firewall.
[TestClass]
public class DetectionPipelineTests
{
    // A known attack is blocked from the heuristic verdict and a firewall rule is created.
    [TestMethod]
    public void ProcessFlow_KnownAttack_ShouldBlockAndCreateRule()
    {
        var inference = new CountingInferenceEngine(CreateDetection());
        var pipeline = CreatePipeline(inference, out var firewall);

        var flow = CreateFlow(PreFilterResult.KnownAttack(AttackTypes.DoS, "SYN flood"));
        var outcome = pipeline.ProcessFlow(flow, new[] { CreatePolicy(DetectionSource.HeuristicBased) });

        Assert.AreEqual(1, inference.CallCount);
        Assert.AreEqual(TrafficVerdict.Malicious, outcome.Verdict);
        Assert.AreEqual(DetectionSource.HeuristicBased, outcome.Alert!.DetectionSource);
        Assert.AreEqual(PolicyAction.BlockInboundIp, outcome.Decision!.Action);
        Assert.HasCount(1, firewall.GetAllRules());
    }

    // A suspicious flow is forwarded to the AI engine, which decides.
    [TestMethod]
    public void ProcessFlow_SuspiciousFlow_ShouldCallInference()
    {
        var inference = new CountingInferenceEngine(CreateDetection());
        var pipeline = CreatePipeline(inference, out _);

        var outcome = pipeline.ProcessFlow(CreateFlow(PreFilterResult.Suspicious("looks odd")), new[] { CreatePolicy() });

        Assert.AreEqual(1, inference.CallCount);
        Assert.AreEqual(TrafficVerdict.Malicious, outcome.Verdict);
    }

    // A benign model answer does not erase the heuristic signal: with detection running at
    // maximum sensitivity the flow is reported as suspicious and monitored, never as normal.
    [TestMethod]
    public void ProcessFlow_BenignInference_ShouldStaySuspicious()
    {
        var inference = new CountingInferenceEngine(CreateDetection(attackType: AttackTypes.Benign, confidence: 0f));
        var pipeline = CreatePipeline(inference, out _);

        var outcome = pipeline.ProcessFlow(CreateFlow(PreFilterResult.Suspicious("looks odd")), new[] { CreatePolicy() });

        Assert.AreEqual(1, inference.CallCount);
        Assert.AreEqual(TrafficVerdict.Suspicious, outcome.Verdict);
        Assert.IsNull(outcome.Alert);
    }

    // An outbound flow is captured and shown, but never treated as an inbound attack: the AI
    // engine is not called and no alert or rule is produced.
    [TestMethod]
    public void ProcessFlow_OutboundFlow_ShouldNotBeTreatedAsAttack()
    {
        var inference = new CountingInferenceEngine(CreateDetection());
        var pipeline = CreatePipeline(inference, out var firewall);

        var flow = CreateFlow(PreFilterResult.KnownAttack(AttackTypes.DoS, "SYN flood"), isInbound: false);

        var outcome = pipeline.ProcessFlow(flow, new[] { CreatePolicy(DetectionSource.HeuristicBased) });

        Assert.AreEqual(TrafficVerdict.Normal, outcome.Verdict);
        Assert.AreEqual(0, inference.CallCount);
        Assert.IsNull(outcome.Alert);
        Assert.IsEmpty(firewall.GetAllRules());
    }

    // Traffic from a source an active rule already blocks is being dropped by the firewall but
    // still reaches the capture driver, so it is reported as blocked, not analysed again.
    [TestMethod]
    public void ProcessFlow_BlockedSource_ShouldBeReportedAsBlocked()
    {
        var inference = new CountingInferenceEngine(CreateDetection());
        var blocked = new BlockedTrafficState();
        blocked.Add("203.0.113.66");
        var pipeline = CreatePipeline(inference, out _, blocked);

        var outcome = pipeline.ProcessFlow(CreateFlow(PreFilterResult.Normal()), new[] { CreatePolicy() });

        Assert.AreEqual(TrafficVerdict.Blocked, outcome.Verdict);
        Assert.AreEqual(0, inference.CallCount);
        Assert.IsNull(outcome.Alert);
    }

    #region Helper Methods

    private static DetectionPipeline CreatePipeline(IInferenceEngine inference, out WindowsFirewallEnforcer firewall,
        BlockedTrafficState? blocked = null)
    {
        var clock = new FakeTimeProvider();
        firewall = new WindowsFirewallEnforcer(new FakeRuleRepository(), new FakeFirewallGateway(),
            new FirewallRuntimeState(dryRun: true), clock, NullLogger<WindowsFirewallEnforcer>.Instance);

        var policy = new PolicyEngine(NullLogger<PolicyEngine>.Instance);
        return new DetectionPipeline(inference, policy, firewall, new FakeUnitOfWork(),
            NullLogger<DetectionPipeline>.Instance, detection: null, blocked: blocked);
    }

    private static Policy CreatePolicy(DetectionSource? source = DetectionSource.RandomForest) => new()
    {
        Id = "P-1",
        Name = "P-1",
        UserId = "admin",
        DetectionSource = source,
        Action = PolicyAction.BlockInboundIp,
        BlockDurationMinutes = 60,
        Priority = 100,
        IsEnabled = true
    };

    private static Alert CreateDetection(
        string attackType = AttackTypes.DoS,
        float confidence = 0.95f,
        DetectionSource source = DetectionSource.RandomForest) => new()
    {
        DetectionSource = source,
        AttackType = attackType,
        ConfidenceScore = confidence,
        SourceIp = "203.0.113.66",
        DestinationIp = "192.168.1.10",
        DestinationPort = 80,
        Protocol = ProtocolNumbers.Tcp
    };

    private static FlowFeatureVector CreateFlow(PreFilterResult verdict, bool isInbound = true) => new()
    {
        Features = new float[20],
        SourceIp = "203.0.113.66",
        SourcePort = 12345,
        DestinationIp = "192.168.1.10",
        DestinationPort = 80,
        Protocol = ProtocolNumbers.Tcp,
        FlowStartTime = DateTime.UnixEpoch,
        FlowEndTime = DateTime.UnixEpoch.AddSeconds(1),
        PreFilterVerdict = verdict,
        // The pipeline only treats inbound flows as attacks; these tests exercise that path.
        IsInbound = isInbound
    };

    private class CountingInferenceEngine : IInferenceEngine
    {
        private readonly Alert _result;

        public int CallCount { get; private set; }

        public CountingInferenceEngine(Alert result)
        {
            _result = result;
        }

        public Alert Detect(FlowFeatureVector flow) => Detect(flow, ModelCombination.RandomForestOnly);

        public Alert Detect(FlowFeatureVector flow, ModelCombination combination)
        {
            CallCount++;
            return new Alert
            {
                DetectionSource = _result.DetectionSource,
                AttackType = _result.AttackType,
                ConfidenceScore = _result.ConfidenceScore,
                SourceIp = flow.SourceIp,
                SourcePort = flow.SourcePort,
                DestinationIp = flow.DestinationIp,
                DestinationPort = flow.DestinationPort,
                Protocol = flow.Protocol
            };
        }
    }

    #endregion
}

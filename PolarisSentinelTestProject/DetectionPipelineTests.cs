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

[TestClass]
public class DetectionPipelineTests
{
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

    [TestMethod]
    public void ProcessFlow_SuspiciousFlow_ShouldCallInference()
    {
        var inference = new CountingInferenceEngine(CreateDetection());
        var pipeline = CreatePipeline(inference, out _);

        var outcome = pipeline.ProcessFlow(CreateFlow(PreFilterResult.Suspicious("looks odd")), new[] { CreatePolicy() });

        Assert.AreEqual(1, inference.CallCount);
        Assert.AreEqual(TrafficVerdict.Malicious, outcome.Verdict);
    }

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

    [TestMethod]
    public void ProcessFlow_ExistingInactiveRule_ShouldNotMarkAddressAsBlocked()
    {
        var inference = new CountingInferenceEngine(CreateDetection());
        var rules = new FakeRuleRepository();
        var blocked = new BlockedTrafficState();

        rules.Add(new Rule
        {
            Id = "R-1",
            Name = EntityIds.FirewallRule($"{PolicyAction.BlockInboundIp}_203.0.113.66"),
            Action = PolicyAction.BlockInboundIp,
            Status = RuleStatus.Inactive,
            SourceIp = "203.0.113.66",
            DestinationIp = "192.168.1.10",
            Protocol = ProtocolNumbers.Tcp,
            CreatedAt = DateTime.UnixEpoch,
            UpdatedAt = DateTime.UnixEpoch,
            ExpiresAt = DateTime.Now.AddYears(1)
        });

        var pipeline = CreatePipeline(inference, out _, blocked, rules);

        var outcome = pipeline.ProcessFlow(
            CreateFlow(PreFilterResult.KnownAttack(AttackTypes.DoS, "SYN flood")),
            new[] { CreatePolicy(DetectionSource.HeuristicBased) });

        Assert.AreEqual(PolicyAction.BlockInboundIp, outcome.Decision!.Action);
        Assert.IsNotNull(outcome.Rule);
        Assert.AreEqual(RuleStatus.Inactive, outcome.Rule!.Status);
        Assert.IsFalse(blocked.IsBlocked("203.0.113.66"));
    }

    #region Helper Methods

    private static DetectionPipeline CreatePipeline(IInferenceEngine inference, out WindowsFirewallEnforcer firewall,
        BlockedTrafficState? blocked = null, FakeRuleRepository? rules = null)
    {
        var clock = new FakeTimeProvider();
        firewall = new WindowsFirewallEnforcer(rules ?? new FakeRuleRepository(), new FakeFirewallGateway(),
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

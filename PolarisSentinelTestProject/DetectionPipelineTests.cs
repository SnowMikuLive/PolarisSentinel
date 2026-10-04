using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Application;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.FirewallEnforement;
using PolarisSentinel.PolicyDecision;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class DetectionPipelineTests
    {
        // A normal flow stops at the pre-filter: the AI engine is not called.
        [TestMethod]
        public void ProcessFlow_NormalFlow_ShouldNotCallInference()
        {
            var inference = new CountingInferenceEngine(CreateDetection());
            var pipeline = CreatePipeline(inference, out _);

            var outcome = pipeline.ProcessFlow(CreateFlow(PreFilterResult.Normal()), new[] { CreatePolicy() });

            Assert.AreEqual(TrafficVerdict.Normal, outcome.Verdict);
            Assert.AreEqual(0, inference.CallCount);
            Assert.IsNull(outcome.Alert);
        }

        // A known attack is alerted straight from the pre-filter, without inference.
        [TestMethod]
        public void ProcessFlow_KnownAttack_ShouldAlertWithoutInference()
        {
            var inference = new CountingInferenceEngine(CreateDetection());
            var pipeline = CreatePipeline(inference, out var firewall);

            var flow = CreateFlow(PreFilterResult.KnownAttack(AttackTypes.DoS, "SYN flood"));
            var outcome = pipeline.ProcessFlow(flow, new[] { CreatePolicy(DetectionSource.HeuristicBased) });

            Assert.AreEqual(0, inference.CallCount);
            Assert.AreEqual(TrafficVerdict.Malicious, outcome.Verdict);
            Assert.AreEqual(DetectionSource.HeuristicBased, outcome.Alert!.DetectionSource);
            Assert.IsNull(outcome.Alert.ConfidenceScore);
            Assert.AreEqual(PolicyAction.BlockInboundIp, outcome.Decision!.Action);
            Assert.HasCount(1, firewall.GetAllRules());
        }

        // A suspicious flow is forwarded to the AI engine.
        [TestMethod]
        public void ProcessFlow_SuspiciousFlow_ShouldCallInference()
        {
            var inference = new CountingInferenceEngine(CreateDetection());
            var pipeline = CreatePipeline(inference, out _);

            var outcome = pipeline.ProcessFlow(CreateFlow(PreFilterResult.Suspicious("looks odd")), new[] { CreatePolicy() });

            Assert.AreEqual(1, inference.CallCount);
            Assert.AreEqual(TrafficVerdict.Malicious, outcome.Verdict);
        }

        // An AI anomaly below the policy threshold is suspicious, not malicious.
        [TestMethod]
        public void ProcessFlow_BelowThreshold_ShouldBeSuspicious()
        {
            var detection = CreateDetection(confidence: 0.4f);
            var pipeline = CreatePipeline(new CountingInferenceEngine(detection), out var firewall);

            var outcome = pipeline.ProcessFlow(
                CreateFlow(PreFilterResult.Suspicious("looks odd")),
                new[] { CreatePolicy(rfThreshold: 0.8f) });

            Assert.AreEqual(TrafficVerdict.Suspicious, outcome.Verdict);
            Assert.IsNull(outcome.Alert);
            Assert.IsEmpty(firewall.GetAllRules());
        }

        // The firewall rule links back to the alert that produced it.
        [TestMethod]
        public void ProcessFlow_BlockDecision_ShouldCreateLinkedRule()
        {
            var pipeline = CreatePipeline(new CountingInferenceEngine(CreateDetection()), out var firewall);

            var outcome = pipeline.ProcessFlow(CreateFlow(PreFilterResult.Suspicious("looks odd")), new[] { CreatePolicy() });

            Assert.AreEqual(PolicyAction.BlockInboundIp, outcome.Decision!.Action);
            var rule = firewall.GetAllRules().Single();
            Assert.AreEqual(outcome.Alert!.Id, rule.AlertId);
            Assert.AreEqual("P-1", rule.PolicyId);
        }

        // A benign AI result produces no alert even though inference ran.
        [TestMethod]
        public void ProcessFlow_BenignAiResult_ShouldBeNormal()
        {
            var detection = CreateDetection(attackType: AttackTypes.Benign, source: DetectionSource.None);
            var pipeline = CreatePipeline(new CountingInferenceEngine(detection), out _);

            var outcome = pipeline.ProcessFlow(CreateFlow(PreFilterResult.Suspicious("looks odd")), new[] { CreatePolicy() });

            Assert.AreEqual(TrafficVerdict.Normal, outcome.Verdict);
            Assert.IsNull(outcome.Alert);
        }

        [TestMethod]
        public void ProcessFlow_UnknownAnomaly_ShouldAlertWithoutFirewallRule()
        {
            var detection = CreateDetection(attackType: AttackTypes.UnknownAnomaly, source: DetectionSource.IsolationForest);
            var pipeline = CreatePipeline(new CountingInferenceEngine(detection), out var firewall);

            var outcome = pipeline.ProcessFlow(CreateFlow(PreFilterResult.Suspicious("test")),
                new[] { CreatePolicy(DetectionSource.IsolationForest) });

            Assert.IsNotNull(outcome.Alert);
            Assert.AreEqual(PolicyAction.Monitor, outcome.Decision!.Action);
            Assert.IsEmpty(firewall.GetAllRules());
        }

        #region Helper Methods

        private static DetectionPipeline CreatePipeline(IInferenceEngine inference, out WindowsFirewallEnforcer firewall)
        {
            var clock = new FakeTimeProvider();
            firewall = new WindowsFirewallEnforcer(new FakeRuleRepository(),
                Options.Create(new FirewallOptions()), new FirewallRuntimeState(dryRun: true), clock, NullLogger<WindowsFirewallEnforcer>.Instance);

            var policy = new PolicyEngine(NullLogger<PolicyEngine>.Instance);
            return new DetectionPipeline(inference, policy, firewall, new FakeUnitOfWork(),
                NullLogger<DetectionPipeline>.Instance);
        }

        private static Policy CreatePolicy(
            DetectionSource? source = DetectionSource.RandomForest,
            float? rfThreshold = null) => new()
        {
            Id = "P-1",
            Name = "P-1",
            UserId = "admin",
            DetectionSource = source,
            RfThreshold = rfThreshold,
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

        private static FlowFeatureVector CreateFlow(PreFilterResult verdict) => new()
        {
            Features = new float[20],
            SourceIp = "203.0.113.66",
            SourcePort = 12345,
            DestinationIp = "192.168.1.10",
            DestinationPort = 80,
            Protocol = ProtocolNumbers.Tcp,
            FlowStartTime = DateTime.UnixEpoch,
            FlowEndTime = DateTime.UnixEpoch.AddSeconds(1),
            PreFilterVerdict = verdict
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
}

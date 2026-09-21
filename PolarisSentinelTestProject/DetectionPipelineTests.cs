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
        #region Pipeline Tests

        // A high-confidence model detection blocks and creates a firewall rule.
        [TestMethod]
        public void DetectionPipeline_RandomForestAttack_ShouldBlockAndCreateRule()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var pipeline = CreatePipeline(CreateDetection(), clock, firewall);
            var policy = CreatePolicy();

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.66"), policy);

            Assert.AreEqual(PolicyAction.Block, decision.Action);
            Assert.AreEqual(DetectionSource.RandomForest, decision.Source);
            Assert.AreEqual("PolarisSentinel_Block_A-RF-1", decision.RuleName);
            Assert.HasCount(1, firewall.GetAllRules());
        }

        // A pre-filter verdict skips inference entirely and blocks without a confidence check.
        [TestMethod]
        public void DetectionPipeline_PreFilterVerdict_ShouldBlockWithoutInference()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var inference = new CountingInferenceEngine(CreateDetection());
            var pipeline = CreatePipeline(inference, clock, firewall);

            var flow = CreateFlow("203.0.113.66");
            var preFilterFlow = new FlowFeatureVector
            {
                Features = flow.Features,
                SourceIp = flow.SourceIp,
                SourcePort = flow.SourcePort,
                DestinationIp = flow.DestinationIp,
                DestinationPort = flow.DestinationPort,
                Protocol = flow.Protocol,
                FlowStartTime = flow.FlowStartTime,
                FlowEndTime = flow.FlowEndTime,
                PreFilterVerdict = new PreFilterResult
                {
                    AttackType = AttackTypes.DoS,
                    Confidence = 1f,
                    Reason = "prefilter_syn_flood"
                }
            };

            var decision = pipeline.ProcessFlow(preFilterFlow, CreatePolicy(DetectionSource.PreFilter));

            Assert.AreEqual(0, inference.CallCount);
            Assert.AreEqual(PolicyAction.Block, decision.Action);
            Assert.AreEqual(DetectionSource.PreFilter, decision.Source);
            Assert.StartsWith("A-PF-", decision.Id);
        }

        // An Isolation Forest anomaly with high confidence blocks like any other detection.
        [TestMethod]
        public void DetectionPipeline_UnknownAnomaly_ShouldBlockAndCreateRule()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var detection = CreateDetection(AttackTypes.UnknownAnomaly, 0.99f, DetectionSource.IsolationForest);
            var pipeline = CreatePipeline(detection, clock, firewall);

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.66"), CreatePolicy(DetectionSource.IsolationForest));

            Assert.AreEqual(PolicyAction.Block, decision.Action);
            Assert.HasCount(1, firewall.GetAllRules());
        }

        // Private addresses are downgraded to Monitor and create no rule.
        [TestMethod]
        public void DetectionPipeline_PrivateIp_ShouldMonitorWithoutRule()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var detection = CreateDetection(sourceIp: "192.168.1.5");
            var pipeline = CreatePipeline(detection, clock, firewall);

            var decision = pipeline.ProcessFlow(CreateFlow("192.168.1.5"), CreatePolicy());

            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.IsNull(decision.RuleName);
            Assert.IsEmpty(firewall.GetAllRules());
        }

        #endregion

        #region Helper Methods

        private static WindowsFirewallEnforcer CreateFirewall(FakeTimeProvider clock)
        {
            return new WindowsFirewallEnforcer(new FakeRuleRepository(),
                Options.Create(new FirewallOptions()), clock, NullLogger<WindowsFirewallEnforcer>.Instance);
        }

        private static DetectionPipeline CreatePipeline(Alert detection, FakeTimeProvider clock,
            WindowsFirewallEnforcer firewall)
        {
            return CreatePipeline(new CountingInferenceEngine(detection), clock, firewall);
        }

        private static DetectionPipeline CreatePipeline(IInferenceEngine inference, FakeTimeProvider clock,
            WindowsFirewallEnforcer firewall)
        {
            var policy = new PolicyEngine(clock, NullLogger<PolicyEngine>.Instance);
            return new DetectionPipeline(inference, policy, firewall, NullLogger<DetectionPipeline>.Instance);
        }

        private static Policy CreatePolicy(DetectionSource source = DetectionSource.RandomForest) => new()
        {
            Id = "P-1",
            DetectionSource = source,
            RfConfidenceThreshold = 0.6f,
            IfConfidenceThreshold = 0.6f,
            BlockDurationMinutes = 60,
            DecisionCooldownSeconds = 60
        };

        private static Alert CreateDetection(string attackType = AttackTypes.DoS, float confidence = 0.95f,
            DetectionSource source = DetectionSource.RandomForest, string sourceIp = "203.0.113.66") => new()
        {
            SourceIp = sourceIp,
            DestinationIp = "192.168.1.10",
            AttackType = attackType,
            Confidence = confidence,
            Source = source,
            Reason = string.Empty
        };

        private static FlowFeatureVector CreateFlow(string sourceIp) => new()
        {
            Features = new float[20],
            SourceIp = sourceIp,
            SourcePort = 12345,
            DestinationIp = "192.168.1.10",
            DestinationPort = 80,
            Protocol = 6,
            FlowStartTime = DateTime.UnixEpoch,
            FlowEndTime = DateTime.UnixEpoch.AddSeconds(1)
        };

        // Returns a fresh copy each call because the policy engine mutates the alert in place.
        private class CountingInferenceEngine : IInferenceEngine
        {
            private readonly Alert _result;

            public int CallCount { get; private set; }

            public CountingInferenceEngine(Alert result)
            {
                _result = result;
            }

            public Alert Detect(FlowFeatureVector flow)
            {
                CallCount++;
                return new Alert
                {
                    SourceIp = _result.SourceIp,
                    SourcePort = _result.SourcePort,
                    DestinationIp = _result.DestinationIp,
                    DestinationPort = _result.DestinationPort,
                    Protocol = _result.Protocol,
                    AttackType = _result.AttackType,
                    Confidence = _result.Confidence,
                    Source = _result.Source,
                    DetectedAt = _result.DetectedAt,
                    Reason = _result.Reason
                };
            }
        }

        #endregion
    }
}

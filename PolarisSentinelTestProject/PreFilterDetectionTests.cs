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
    public class PreFilterDetectionTests
    {
        // A known pre-filter attack blocks immediately and never reaches inference.
        [TestMethod]
        public void PreFilterVerdict_ShouldBlockImmediately()
        {
            var inference = new CountingInferenceEngine();
            var pipeline = CreatePipeline(inference, out var firewall);

            var outcome = pipeline.ProcessFlow(CreateFlow(AttackTypes.DoS), new[] { CreatePolicy() });

            Assert.AreEqual(0, inference.CallCount);
            Assert.AreEqual(PolicyAction.BlockInboundIp, outcome.Decision!.Action);
            Assert.AreEqual(DetectionSource.HeuristicBased, outcome.Alert!.DetectionSource);
            Assert.AreEqual("policy_block", outcome.Decision.Reason);
            Assert.HasCount(1, firewall.GetAllRules());
        }

        // A pre-filter alert carries no model confidence.
        [TestMethod]
        public void PreFilterVerdict_ShouldHaveNullConfidence()
        {
            var pipeline = CreatePipeline(new CountingInferenceEngine(), out _);

            var outcome = pipeline.ProcessFlow(CreateFlow(AttackTypes.PortScan), new[] { CreatePolicy() });

            Assert.IsNull(outcome.Alert!.ConfidenceScore);
            Assert.AreEqual("PortScan", outcome.Alert.AttackType);
        }

        // The firewall rule name contains the alert id.
        [TestMethod]
        public void PreFilterVerdict_ShouldUseAlertIdInRuleName()
        {
            var pipeline = CreatePipeline(new CountingInferenceEngine(), out var firewall);

            var outcome = pipeline.ProcessFlow(CreateFlow(AttackTypes.DoS), new[] { CreatePolicy() });

            Assert.AreEqual($"PolarisSentinel_Block_{outcome.Alert!.Id}", outcome.Rule!.Name);
            Assert.AreEqual(outcome.Rule.Name, firewall.GetAllRules()[0].Name);
        }

        // The pre-filter alert carries the flow's 5-tuple and flag counters.
        [TestMethod]
        public void PreFilterVerdict_ShouldCarryFiveTupleAndFlags()
        {
            var pipeline = CreatePipeline(new CountingInferenceEngine(), out _);

            var outcome = pipeline.ProcessFlow(CreateFlow(AttackTypes.DoS), new[] { CreatePolicy() });

            var alert = outcome.Alert!;
            Assert.AreEqual("203.0.113.9", alert.SourceIp);
            Assert.AreEqual(12345, alert.SourcePort);
            Assert.AreEqual("192.168.1.10", alert.DestinationIp);
            Assert.AreEqual(80, alert.DestinationPort);
            Assert.AreEqual(ProtocolNumbers.Tcp, alert.Protocol);
            Assert.AreEqual(1500, alert.SynCount);
        }

        // The flow snapshot is persisted for the alert detail page.
        [TestMethod]
        public void PreFilterVerdict_ShouldStoreFlowSnapshot()
        {
            var pipeline = CreatePipeline(new CountingInferenceEngine(), out _);

            var outcome = pipeline.ProcessFlow(CreateFlow(AttackTypes.DoS), new[] { CreatePolicy() });

            var snapshot = FlowSnapshot.Read(outcome.Alert!.FlowSnapshotJson);
            Assert.IsNotEmpty(snapshot);
            Assert.IsTrue(snapshot.Any(kv => kv.Key == "flow_duration_ms"));
            Assert.IsTrue(snapshot.Any(kv => kv.Key == "syn_count"));
        }

        // A pre-filter attack that no policy matches is still alerted, just monitored.
        [TestMethod]
        public void PreFilterVerdict_NoMatchingPolicy_ShouldStillAlert()
        {
            var pipeline = CreatePipeline(new CountingInferenceEngine(), out var firewall);
            var policy = CreatePolicy();
            policy.AttackType = AttackTypes.BruteForce;

            var outcome = pipeline.ProcessFlow(CreateFlow(AttackTypes.DoS), new[] { policy });

            Assert.AreEqual(TrafficVerdict.Malicious, outcome.Verdict);
            Assert.AreEqual(PolicyAction.Monitor, outcome.Decision!.Action);
            Assert.IsEmpty(firewall.GetAllRules());
        }

        // The generated rule records the blocked address on the destination too, so the
        // Rules view shows the IP instead of "Any".
        [TestMethod]
        public void PreFilterVerdict_BlockRule_ShouldExposeBlockedAddressAsDestination()
        {
            var pipeline = CreatePipeline(new CountingInferenceEngine(), out _);

            var outcome = pipeline.ProcessFlow(CreateFlow(AttackTypes.DoS), new[] { CreatePolicy() });

            var rule = outcome.Rule!;
            Assert.AreEqual(PolicyAction.BlockInboundIp, rule.Action);
            Assert.AreEqual("203.0.113.9", rule.SourceIp);
            Assert.AreEqual("203.0.113.9", rule.DestinationIp);
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

        private static Policy CreatePolicy() => new()
        {
            Id = "P-1",
            Name = "P-1",
            UserId = "admin",
            DetectionSource = DetectionSource.HeuristicBased,
            Action = PolicyAction.BlockInboundIp,
            BlockDurationMinutes = 60,
            Priority = 100,
            IsEnabled = true
        };

        private static FlowFeatureVector CreateFlow(string attackType) => new()
        {
            Features = new float[20],
            SourceIp = "203.0.113.9",
            SourcePort = 12345,
            DestinationIp = "192.168.1.10",
            DestinationPort = 80,
            Protocol = ProtocolNumbers.Tcp,
            FlowStartTime = DateTime.UnixEpoch,
            FlowEndTime = DateTime.UnixEpoch.AddSeconds(1),
            SynCount = 1500,
            PreFilterVerdict = PreFilterResult.KnownAttack(attackType, $"prefilter_{attackType.ToLowerInvariant()}")
        };

        private class CountingInferenceEngine : IInferenceEngine
        {
            public int CallCount { get; private set; }

            public Alert Detect(FlowFeatureVector flow) => Detect(flow, ModelCombination.RandomForestOnly);

            public Alert Detect(FlowFeatureVector flow, ModelCombination combination)
            {
                CallCount++;
                return new Alert
                {
                    DetectionSource = DetectionSource.RandomForest,
                    AttackType = AttackTypes.DoS,
                    ConfidenceScore = 0.99f,
                    SourceIp = flow.SourceIp,
                    DestinationIp = flow.DestinationIp
                };
            }
        }

        #endregion
    }
}

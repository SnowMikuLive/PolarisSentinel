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
        // The alert carries the flow 5-tuple and the flow/behavior snapshots for the detail page.
        [TestMethod]
        public void PreFilterVerdict_ShouldCarrySnapshots()
        {
            var pipeline = CreatePipeline(new CountingInferenceEngine(), out _);
            var flow = CreateFlow(AttackTypes.PortScan);
            flow = new FlowFeatureVector
            {
                Features = flow.Features,
                SourceIp = flow.SourceIp,
                SourcePort = flow.SourcePort,
                DestinationIp = flow.DestinationIp,
                DestinationPort = flow.DestinationPort,
                Protocol = flow.Protocol,
                FlowStartTime = flow.FlowStartTime,
                FlowEndTime = flow.FlowEndTime,
                PreFilterVerdict = PreFilterResult.KnownAttack(
                    AttackTypes.PortScan, "Port scan", new BehaviorWindowStats(10, 10, 1, 10, 0, 0, 0, 10, new[] { 80, 443 }))
            };

            var outcome = pipeline.ProcessFlow(flow, new[] { CreatePolicy() });

            var alert = outcome.Alert!;
            Assert.AreEqual("203.0.113.9", alert.SourceIp);
            Assert.AreEqual(12345, alert.SourcePort);
            Assert.AreEqual("192.168.1.10", alert.DestinationIp);
            Assert.AreEqual(80, alert.DestinationPort);
            Assert.IsTrue(FlowSnapshot.Read(alert.FlowSnapshotJson).Any(kv => kv.Key == "flow_duration_ms"));
            Assert.IsTrue(BehaviorSnapshot.Read(alert.BehaviorSnapshotJson).Any(kv => kv.Key == "distinct_ports"));
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

        // The rule mirrors the alert 5-tuple; the inbound-IP action blocks the source address.
        [TestMethod]
        public void PreFilterVerdict_BlockRule_ShouldMirrorAlertAndExposeBlockedIp()
        {
            var pipeline = CreatePipeline(new CountingInferenceEngine(), out _);

            var outcome = pipeline.ProcessFlow(CreateFlow(AttackTypes.DoS), new[] { CreatePolicy() });

            var rule = outcome.Rule!;
            Assert.AreEqual(outcome.Alert!.SourceIp, rule.SourceIp);
            Assert.AreEqual(outcome.Alert.DestinationIp, rule.DestinationIp);
            Assert.IsTrue(rule.BlocksAddress);
            Assert.AreEqual("203.0.113.9", rule.BlockedIp);
        }

        // A spoofed/random-source flood targets the destination instead of the fake source,
        // so the inbound-IP policy blocks traffic to the victim.
        [TestMethod]
        public void PreFilterVerdict_SpoofedFlood_ShouldBlockDestination()
        {
            var pipeline = CreatePipeline(new CountingInferenceEngine(), out _);
            var flow = CreateFlow(AttackTypes.DoS);
            flow = new FlowFeatureVector
            {
                Features = flow.Features,
                SourceIp = "203.0.113.9",
                SourcePort = flow.SourcePort,
                DestinationIp = "192.168.1.10",
                DestinationPort = flow.DestinationPort,
                Protocol = flow.Protocol,
                FlowStartTime = flow.FlowStartTime,
                FlowEndTime = flow.FlowEndTime,
                PreFilterVerdict = PreFilterResult.SpoofedFlood(AttackTypes.DoS, "Global flood")
            };

            var outcome = pipeline.ProcessFlow(flow, new[] { CreatePolicy() });

            Assert.AreEqual("192.168.1.10", outcome.Alert!.SourceIp);
            Assert.AreEqual("192.168.1.10", outcome.Rule!.BlockedIp);
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

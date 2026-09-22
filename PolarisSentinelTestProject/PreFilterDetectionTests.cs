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
        #region Pipeline Tests

        // A pre-filter verdict is treated like a model detection and blocks immediately.
        [TestMethod]
        public void PreFilterVerdict_ShouldBlockImmediately()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var pipeline = CreatePipeline(clock, firewall);

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.9", AttackTypes.DoS), CreatePolicy());

            Assert.AreEqual(PolicyAction.Block, decision.Action);
            Assert.AreEqual(DetectionSource.PreFilter, decision.Source);
            Assert.AreEqual("attack_detected", decision.Reason);
            Assert.HasCount(1, firewall.GetAllRules());
        }

        // 唯一编号和检测来源分开保存。
        // Store the unique ID separately from its source.
        [TestMethod]
        public void PreFilterVerdict_ShouldKeepSourceWithUniqueId()
        {
            var clock = new FakeTimeProvider();
            var pipeline = CreatePipeline(clock, CreateFirewall(clock));

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.9", AttackTypes.PortScan), CreatePolicy());

            Assert.IsTrue(Guid.TryParseExact(decision.Id, "N", out _));
            Assert.AreEqual(DetectionSource.PreFilter, decision.Source);
        }

        // 规则名保留告警编号。
        // Keep the alert ID in the firewall rule name.
        [TestMethod]
        public void PreFilterVerdict_ShouldUseAlertIdInRuleName()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var pipeline = CreatePipeline(clock, firewall);

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.9", AttackTypes.DoS), CreatePolicy());

            Assert.IsTrue(Guid.TryParseExact(decision.Id, "N", out _));
            Assert.AreEqual(DetectionSource.PreFilter, decision.Source);
            Assert.AreEqual($"PolarisSentinel_Block_{decision.Id}", decision.RuleName);
            Assert.AreEqual(decision.RuleName, firewall.GetAllRules()[0].Name);
        }

        // Every detection source maps onto its own alert tag.
        [TestMethod]
        public void AlertId_ShouldTagEveryDetectionSource()
        {
            Assert.AreEqual("A-PF-7", EntityIds.Alert(DetectionSource.PreFilter, 7));
            Assert.AreEqual("A-RF-7", EntityIds.Alert(DetectionSource.RandomForest, 7));
            Assert.AreEqual("A-IF-7", EntityIds.Alert(DetectionSource.IsolationForest, 7));
        }

        // 未匹配策略也保留来源。
        // Keep the source even when no policy matches.
        [TestMethod]
        public void PreFilterVerdict_NoMatch_ShouldKeepSourceWithUniqueId()
        {
            var clock = new FakeTimeProvider();
            var pipeline = CreatePipeline(clock, CreateFirewall(clock));
            var policy = CreatePolicy();
            policy.MatchAttackTypes = AttackTypes.BruteForce;

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.9", AttackTypes.DoS), policy);

            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.IsTrue(Guid.TryParseExact(decision.Id, "N", out _));
            Assert.AreEqual(DetectionSource.PreFilter, decision.Source);
        }

        // The pre-filter alert carries the flow's 5-tuple.
        [TestMethod]
        public void PreFilterVerdict_ShouldCarryFiveTuple()
        {
            var clock = new FakeTimeProvider();
            var pipeline = CreatePipeline(clock, CreateFirewall(clock));

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.9", AttackTypes.DoS), CreatePolicy());

            Assert.AreEqual("203.0.113.9", decision.SourceIp);
            Assert.AreEqual(12345, decision.SourcePort);
            Assert.AreEqual("192.168.1.10", decision.DestinationIp);
            Assert.AreEqual(80, decision.DestinationPort);
            Assert.AreEqual(6, decision.Protocol);
        }

        #endregion

        #region Helper Methods

        private static WindowsFirewallEnforcer CreateFirewall(FakeTimeProvider clock)
        {
            return new WindowsFirewallEnforcer(new FakeRuleRepository(),
                Options.Create(new FirewallOptions()), clock, NullLogger<WindowsFirewallEnforcer>.Instance);
        }

        private static DetectionPipeline CreatePipeline(FakeTimeProvider clock, WindowsFirewallEnforcer firewall)
        {
            var policy = new PolicyEngine(clock, NullLogger<PolicyEngine>.Instance);
            return new DetectionPipeline(new NoopInferenceEngine(), policy, firewall, new FakeUnitOfWork(),
                NullLogger<DetectionPipeline>.Instance);
        }

        private static Policy CreatePolicy() => new()
        {
            Id = "P-1",
            DetectionSource = DetectionSource.PreFilter,
            RfConfidenceThreshold = 0.6f,
            IfConfidenceThreshold = 0.6f,
            BlockDurationMinutes = 60
        };

        private static FlowFeatureVector CreateFlow(string sourceIp, string attackType) => new()
        {
            Features = new float[20],
            SourceIp = sourceIp,
            SourcePort = 12345,
            DestinationIp = "192.168.1.10",
            DestinationPort = 80,
            Protocol = 6,
            FlowStartTime = DateTime.UnixEpoch,
            FlowEndTime = DateTime.UnixEpoch.AddSeconds(1),
            PreFilterVerdict = new PreFilterResult
            {
                AttackType = attackType,
                Confidence = 1f,
                Reason = $"prefilter_{attackType}"
            }
        };

        // Pre-filter flows never reach inference; this proves it by returning a benign result.
        private class NoopInferenceEngine : IInferenceEngine
        {
            public Alert Detect(FlowFeatureVector flow) => new()
            {
                SourceIp = flow.SourceIp,
                DestinationIp = flow.DestinationIp,
                AttackType = AttackTypes.Benign,
                Confidence = 0f,
                Source = DetectionSource.None,
                Reason = string.Empty
            };
        }

        #endregion
    }
}

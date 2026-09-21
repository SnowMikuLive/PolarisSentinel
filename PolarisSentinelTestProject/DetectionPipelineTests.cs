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

        //冷却结束后同IP复用原防火墙规则
        //Reuse the original firewall rule for the same IP after cooldown
        [TestMethod]
        public void DetectionPipeline_RandomForestAttack_ShouldBlockAndReuseRule()
        {
            // Arrange
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var detection = new Alert
            {
                SourceIp = "203.0.113.66",
                DestinationIp = "192.168.1.10",
                AttackType = AttackTypes.DoS,
                Confidence = 0.95f,
                Source = DetectionSource.RandomForest,
                Reason = string.Empty
            };
            var pipeline = CreatePipeline(detection, clock, firewall);
            var flow = CreateFlow(detection.SourceIp);

            // Act
            var first = pipeline.ProcessFlow(flow);
            clock.Advance(TimeSpan.FromSeconds(61));
            var second = pipeline.ProcessFlow(flow);
            var rules = firewall.GetAllRules().ToList();

            // Assert
            Assert.IsTrue(firewall.IsDryRun);
            Assert.AreEqual(PolicyAction.Block, first.Action);
            Assert.AreEqual(PolicyAction.Block, second.Action);
            Assert.AreEqual(DetectionSource.RandomForest, first.DetectionSource);
            Assert.HasCount(1, rules);
            Assert.AreEqual(EntityIds.FirewallRule(first.AlertId), rules[0].Name);
            Assert.AreEqual(rules[0].Name, first.RuleName);
            Assert.AreEqual(first.RuleName, second.RuleName);
            Assert.AreNotEqual(first.AlertId, second.AlertId);
        }

        [TestMethod]
        public void DetectionPipeline_UnknownAnomaly_ShouldMonitorWithoutRule()
        {
            // Arrange
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var detection = new Alert
            {
                SourceIp = "203.0.113.66",
                DestinationIp = "192.168.1.10",
                AttackType = AttackTypes.UnknownAnomaly,
                Confidence = 0.99f,
                Source = DetectionSource.IsolationForest,
                Reason = string.Empty
            };
            var pipeline = CreatePipeline(detection, clock, firewall);

            // Act
            var decision = pipeline.ProcessFlow(CreateFlow(detection.SourceIp));

            // Assert
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual(DetectionSource.IsolationForest, decision.DetectionSource);
            Assert.IsNull(decision.RuleName);
            Assert.IsEmpty(firewall.GetAllRules());
        }

        //内网高置信度降级为Monitor，不创建规则
        //High-confidence private IP downgrades to Monitor without a rule
        [TestMethod]
        public void DetectionPipeline_PrivateIp_ShouldMonitorWithoutRule()
        {
            // Arrange
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var detection = new Alert
            {
                SourceIp = "192.168.1.5",
                DestinationIp = "192.168.1.10",
                AttackType = AttackTypes.DoS,
                Confidence = 0.95f,
                Source = DetectionSource.RandomForest,
                Reason = string.Empty
            };
            var pipeline = CreatePipeline(detection, clock, firewall);

            // Act
            var decision = pipeline.ProcessFlow(CreateFlow(detection.SourceIp));

            // Assert
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.IsNull(decision.RuleName);
            Assert.IsEmpty(firewall.GetAllRules());
        }

        #endregion

        #region Helper Methods

        //默认DryRun，测试只使用内存规则
        //Default DryRun keeps test rules in memory
        private WindowsFirewallEnforcer CreateFirewall(FakeTimeProvider clock)
        {
            return new WindowsFirewallEnforcer(Options.Create(new FirewallOptions()),
                clock, NullLogger<WindowsFirewallEnforcer>.Instance);
        }

        private DetectionPipeline CreatePipeline(Alert detection, FakeTimeProvider clock,
            WindowsFirewallEnforcer firewall)
        {
            var policy = new PolicyEngine(() => new Policy { Name = string.Empty }, clock,
                NullLogger<PolicyEngine>.Instance);
            return new DetectionPipeline(new TestInferenceEngine(detection), policy, firewall,
                60, NullLogger<DetectionPipeline>.Instance);
        }

        private FlowFeatureVector CreateFlow(string sourceIp)
        {
            return new FlowFeatureVector
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
        }

        //固定推理结果，用来检查后续策略和防火墙流程
        //Fixed inference result for testing policy and firewall together
        private class TestInferenceEngine : IInferenceEngine
        {
            private readonly Alert _result;

            public TestInferenceEngine(Alert result)
            {
                _result = result;
            }

            public Alert Detect(FlowFeatureVector flow)
            {
                return _result;
            }
        }

        #endregion
    }
}

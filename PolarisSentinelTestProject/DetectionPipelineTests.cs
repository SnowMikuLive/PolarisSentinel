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
            Assert.AreEqual(EntityIds.FirewallRule(decision.Id), decision.RuleName);
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
            Assert.IsTrue(Guid.TryParseExact(decision.Id, "N", out _));
        }

        // 未知异常即使高置信度也不封禁。
        // Unknown anomalies never create automatic firewall rules.
        [TestMethod]
        public void DetectionPipeline_UnknownAnomaly_ShouldMonitorWithoutRule()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var detection = CreateDetection(AttackTypes.UnknownAnomaly, 0.99f, DetectionSource.IsolationForest);
            var pipeline = CreatePipeline(detection, clock, firewall);

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.66"), CreatePolicy(DetectionSource.IsolationForest));

            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.IsEmpty(firewall.GetAllRules());
            Assert.IsNull(decision.RuleName);
        }

        // 内网来源只监控。
        // Private sources remain Monitor-only.
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

        // 推理之后匹配具体策略，并把有效期传给执行器。
        // Match after inference and pass the selected duration to enforcement.
        [TestMethod]
        public void PolicySelection_ShouldUseActualAttackAndSource()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var inference = new CountingInferenceEngine(CreateDetection());
            var pipeline = CreatePipeline(inference, clock, firewall);
            var wrongAttack = CreatePolicy();
            wrongAttack.MatchAttackTypes = AttackTypes.PortScan;
            var wrongSource = CreatePolicy(DetectionSource.IsolationForest);
            var fallback = CreatePolicy();
            var selected = CreatePolicy();
            selected.Id = "P-2";
            selected.MatchAttackTypes = AttackTypes.DoS;
            selected.BlockDurationMinutes = 7;
            var policies = new[] { wrongAttack, wrongSource, fallback, selected };

            var result = pipeline.ProcessFlow(CreateFlow("203.0.113.66"), policies);

            Assert.AreEqual(1, inference.CallCount);
            Assert.AreEqual(PolicyAction.Block, result.Action);
            var rule = firewall.GetAllRules().Single();
            Assert.AreEqual("P-2", rule.PolicyId);
            Assert.AreEqual(TimeSpan.FromMinutes(7), rule.ExpiresAt - rule.CreatedAt);
        }

        [TestMethod]
        public void NoEnabledPolicy_ShouldStillSaveMonitorResult()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var uow = new FakeUnitOfWork();
            var pipeline = new DetectionPipeline(new CountingInferenceEngine(CreateDetection()),
                new PolicyEngine(clock, NullLogger<PolicyEngine>.Instance), firewall, uow,
                NullLogger<DetectionPipeline>.Instance);
            var policy = CreatePolicy();
            policy.Enabled = false;

            var result = pipeline.ProcessFlow(CreateFlow("203.0.113.66"), new[] { policy });

            Assert.AreEqual(PolicyAction.Monitor, result.Action);
            Assert.IsNotNull(uow.Alerts.GetByIdAsync(result.Id).Result);
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
            return new DetectionPipeline(inference, policy, firewall, new FakeUnitOfWork(),
                NullLogger<DetectionPipeline>.Instance);
        }

        private static Policy CreatePolicy(DetectionSource source = DetectionSource.RandomForest) => new()
        {
            Id = "P-1",
            DetectionSource = source,
            RfConfidenceThreshold = 0.6f,
            IfConfidenceThreshold = 0.6f,
            BlockDurationMinutes = 60
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

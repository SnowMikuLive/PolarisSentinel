using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Application;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class PolicyEngineUnitTest
    {
        [TestMethod]
        public void EvaluateShouldReturnADecision()
        {
            var decision = Evaluate(CreateAlert(), CreatePolicy());
            Assert.IsNotNull(decision);
            Assert.IsTrue(Enum.IsDefined(typeof(PolicyAction), decision.Action));
        }

        [TestMethod]
        public void EvaluateBenignTrafficShouldMonitor()
        {
            var alert = CreateAlert(attackType: AttackTypes.Benign);
            var decision = Evaluate(alert, CreatePolicy());
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("benign", decision.Reason);
        }

        [TestMethod]
        public void EvaluateMatchingPolicyShouldBlock()
        {
            var decision = Evaluate(CreateAlert(), CreatePolicy());
            Assert.AreEqual(PolicyAction.BlockInboundIp, decision.Action);
            Assert.AreEqual("policy_block", decision.Reason);
            Assert.AreEqual("P-1", decision.PolicyId);
        }

        [TestMethod]
        public void EvaluateDisabledPolicyShouldNotMatch()
        {
            var policy = CreatePolicy();
            policy.IsEnabled = false;
            var decision = Evaluate(CreateAlert(), policy);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("no_matching_policy", decision.Reason);
        }

        [TestMethod]
        public void EvaluateDetectionSourceMismatchShouldNotMatch()
        {
            var policy = CreatePolicy(source: DetectionSource.PreFilter);
            var alert = CreateAlert(source: DetectionSource.RandomForest);
            var decision = Evaluate(alert, policy);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("no_matching_policy", decision.Reason);
        }

        [TestMethod]
        public void EvaluateAttackTypeMismatchShouldNotMatch()
        {
            var policy = CreatePolicy(attackType: AttackTypes.PortScan);
            var decision = Evaluate(CreateAlert(attackType: AttackTypes.DoS), policy);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("no_matching_policy", decision.Reason);
        }

        [TestMethod]
        public void EvaluateRfThresholdShouldBeEnforced()
        {
            var policy = CreatePolicy(rfThreshold: 0.8f);
            var alert = CreateAlert(confidence: 0.5f, source: DetectionSource.RandomForest);
            var decision = Evaluate(alert, policy);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("no_matching_policy", decision.Reason);
        }

        [TestMethod]
        public void EvaluateRfThresholdMetShouldBlock()
        {
            var policy = CreatePolicy(rfThreshold: 0.8f);
            var alert = CreateAlert(confidence: 0.9f, source: DetectionSource.RandomForest);
            var decision = Evaluate(alert, policy);
            Assert.AreEqual(PolicyAction.BlockInboundIp, decision.Action);
        }

        [TestMethod]
        public void EvaluateIfThresholdShouldBeEnforced()
        {
            var policy = CreatePolicy(ifThreshold: 0.8f, source: DetectionSource.IsolationForest);
            var alert = CreateAlert(confidence: 0.5f, source: DetectionSource.IsolationForest, attackType: AttackTypes.UnknownAnomaly);
            var decision = Evaluate(alert, policy);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
        }

        [TestMethod]
        public void EvaluateUnknownAnomalyShouldNeverBlock()
        {
            var policy = CreatePolicy(ifThreshold: 0.6f, source: DetectionSource.IsolationForest);
            var alert = CreateAlert(confidence: 0.99f, source: DetectionSource.IsolationForest, attackType: AttackTypes.UnknownAnomaly);

            var decision = Evaluate(alert, policy);

            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("unknown_anomaly", decision.Reason);
        }

        [TestMethod]
        public void EvaluatePreFilterAlertShouldIgnoreThreshold()
        {
            var policy = CreatePolicy(source: DetectionSource.PreFilter);
            var alert = CreateAlert(confidence: null, source: DetectionSource.PreFilter);
            var decision = Evaluate(alert, policy);
            Assert.AreEqual(PolicyAction.BlockInboundIp, decision.Action);
        }

        [TestMethod]
        public void EvaluateHighestPriorityPolicyShouldBeSelected()
        {
            var low = CreatePolicy(id: "P-1", priority: 50);
            var high = CreatePolicy(id: "P-2", priority: 100);
            var decision = Evaluate(CreateAlert(), low, high);
            Assert.AreEqual("P-2", decision.PolicyId);
        }

        [TestMethod]
        public void EvaluateEqualPriorityShouldBreakTieByCreatedAtThenId()
        {
            var newer = CreatePolicy(id: "P-2", priority: 50, createdAt: new DateTime(2026, 1, 2));
            var older = CreatePolicy(id: "P-1", priority: 50, createdAt: new DateTime(2026, 1, 1));
            var decision = Evaluate(CreateAlert(), newer, older);
            Assert.AreEqual("P-1", decision.PolicyId);
        }

        [TestMethod]
        public void EvaluateMonitorPolicyShouldNotBlock()
        {
            var policy = CreatePolicy(action: PolicyAction.Monitor);
            var decision = Evaluate(CreateAlert(), policy);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("policy_monitor", decision.Reason);
        }

        #region Helper Methods

        private static PolicyDecision Evaluate(Alert alert, params Policy[] policies)
        {
            var engine = new PolicyEngine(NullLogger<PolicyEngine>.Instance);
            return engine.Evaluate(alert, policies);
        }

        private static Policy CreatePolicy(
            string id = "P-1",
            float? rfThreshold = null,
            float? ifThreshold = null,
            DetectionSource? source = null,
            string? attackType = null,
            PolicyAction action = PolicyAction.BlockInboundIp,
            int priority = 0,
            DateTime? createdAt = null)
        {
            return new Policy
            {
                Id = id,
                Name = id,
                UserId = "admin",
                DetectionSource = source,
                RfThreshold = rfThreshold,
                IfThreshold = ifThreshold,
                AttackType = attackType,
                Action = action,
                BlockDurationMinutes = 60,
                Priority = priority,
                IsEnabled = true,
                CreatedAt = createdAt ?? new DateTime(2026, 1, 1),
                UpdatedAt = createdAt ?? new DateTime(2026, 1, 1)
            };
        }

        private static Alert CreateAlert(
            float? confidence = 0.99f,
            string attackType = AttackTypes.DoS,
            DetectionSource source = DetectionSource.RandomForest)
        {
            return new Alert
            {
                Id = "A-1",
                DetectionSource = source,
                AttackType = attackType,
                ConfidenceScore = confidence,
                SourceIp = "8.8.8.8",
                SourcePort = 44444,
                DestinationIp = "192.168.1.10",
                DestinationPort = 80,
                Protocol = ProtocolNumbers.Tcp
            };
        }

        #endregion
    }
}

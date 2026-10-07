using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Application;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;
using PolarisSentinel.PolicyDecision;
using Decision = PolarisSentinel.Core.Models.PolicyDecision;

namespace PolarisSentienlUnitTestProject
{
    // Key policy-matching behaviour: which alerts match, which block, and how the winner is chosen.
    [TestClass]
    public class PolicyEngineUnitTest
    {
        [TestMethod]
        public void EvaluateBenignTrafficShouldMonitor()
        {
            var decision = Evaluate(CreateAlert(attackType: AttackTypes.Benign), CreatePolicy());
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
        public void EvaluateNonMatchingPolicyShouldMonitor()
        {
            var disabled = CreatePolicy();
            disabled.IsEnabled = false;
            var disabledDecision = Evaluate(CreateAlert(), disabled);

            var sourceMismatch = Evaluate(CreateAlert(source: DetectionSource.RandomForest), CreatePolicy(source: DetectionSource.HeuristicBased));
            var typeMismatch = Evaluate(CreateAlert(attackType: AttackTypes.DoS), CreatePolicy(attackType: AttackTypes.PortScan));

            Assert.AreEqual("no_matching_policy", disabledDecision.Reason);
            Assert.AreEqual("no_matching_policy", sourceMismatch.Reason);
            Assert.AreEqual("no_matching_policy", typeMismatch.Reason);
        }

        [TestMethod]
        public void EvaluateThresholdShouldBeEnforced()
        {
            var below = Evaluate(CreateAlert(confidence: 0.5f, source: DetectionSource.RandomForest), CreatePolicy(rfThreshold: 0.8f));
            var met = Evaluate(CreateAlert(confidence: 0.9f, source: DetectionSource.RandomForest), CreatePolicy(rfThreshold: 0.8f));

            Assert.AreEqual(PolicyAction.Monitor, below.Action);
            Assert.AreEqual(PolicyAction.BlockInboundIp, met.Action);
        }

        // An Isolation Forest alert can only ever be Unknown_Anomaly and never blocks.
        [TestMethod]
        public void EvaluateUnknownAnomalyShouldMonitorAndNormalise()
        {
            var policy = CreatePolicy(source: DetectionSource.IsolationForest, attackType: AttackTypes.DoS);
            var alert = CreateAlert(confidence: 0.99f, source: DetectionSource.IsolationForest, attackType: AttackTypes.DoS);

            var decision = Evaluate(alert, policy);

            Assert.AreEqual(AttackTypes.UnknownAnomaly, alert.AttackType);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("unknown_anomaly", decision.Reason);
        }

        // A heuristic alert carries no score, so it always passes the threshold.
        [TestMethod]
        public void EvaluatePreFilterAlertShouldIgnoreThreshold()
        {
            var decision = Evaluate(CreateAlert(confidence: null, source: DetectionSource.HeuristicBased), CreatePolicy(source: DetectionSource.HeuristicBased));
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

        #region Helper Methods

        private static Decision Evaluate(Alert alert, params Policy[] policies)
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

        #endregion
    }
}

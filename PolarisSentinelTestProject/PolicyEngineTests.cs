using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;
using PolarisSentinel.PolicyDecision;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class PolicyEngineUnitTest
    {
        #region Basic Functionality Tests

        [TestMethod]
        public void PolicyEngineEvaluateShouldReturnADecision()
        {
            var engine = CreateEngine();
            var decision = engine.Evaluate(CreateAlert(), CreatePolicy());
            Assert.IsNotNull(decision);
            Assert.IsTrue(Enum.IsDefined(typeof(PolicyAction), decision.Action));
        }

        [TestMethod]
        public void PolicyEngineEvaluateBenignTrafficShouldMonitor()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 0.99f, AttackTypes.Benign, DetectionSource.RandomForest);
            var decision = engine.Evaluate(alert, CreatePolicy());
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("benign", decision.Reason);
        }

        [TestMethod]
        public void PolicyEngineEvaluateHighConfidenceAttackShouldBlock()
        {
            var engine = CreateEngine();
            var decision = engine.Evaluate(CreateAlert(), CreatePolicy());
            Assert.AreEqual(PolicyAction.Block, decision.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluateLowConfidenceShouldMonitor()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 0.50f, AttackTypes.DoS, DetectionSource.RandomForest);
            var decision = engine.Evaluate(alert, CreatePolicy(0.6f));
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("confidence_below_threshold", decision.Reason);
        }

        [TestMethod]
        public void PolicyEngineEvaluateNoDetectionSourceShouldMonitor()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 0.99f, AttackTypes.DoS, DetectionSource.None);
            var decision = engine.Evaluate(alert, CreatePolicy());
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluatePortScanShouldBlockWhenConfidenceIsHigh()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("1.1.1.1", 0.95f, AttackTypes.PortScan, DetectionSource.RandomForest);
            var decision = engine.Evaluate(alert, CreatePolicy());
            Assert.AreEqual(PolicyAction.Block, decision.Action);
        }

        // A null Random Forest threshold disables that detector.
        [TestMethod]
        public void PolicyEngineEvaluateNullRfThresholdShouldMonitor()
        {
            var engine = CreateEngine();
            var decision = engine.Evaluate(CreateAlert(), CreatePolicy(rfThreshold: null));
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
        }

        // Isolation Forest detections use the IF threshold, not the RF one.
        [TestMethod]
        public void PolicyEngineEvaluateIsolationForestUsesIfThreshold()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 0.70f, AttackTypes.DoS, DetectionSource.IsolationForest);
            var policy = CreatePolicy(rfThreshold: 0.9f, ifThreshold: 0.6f, source: DetectionSource.IsolationForest);
            var decision = engine.Evaluate(alert, policy);
            Assert.AreEqual(PolicyAction.Block, decision.Action);
        }

        // An Isolation Forest detection below its threshold is monitored.
        [TestMethod]
        public void PolicyEngineEvaluateIsolationForestBelowIfThresholdShouldMonitor()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 0.50f, AttackTypes.DoS, DetectionSource.IsolationForest);
            var policy = CreatePolicy(rfThreshold: 0.6f, ifThreshold: 0.7f, source: DetectionSource.IsolationForest);
            var decision = engine.Evaluate(alert, policy);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
        }

        // A pre-filter verdict carries confidence 1, so it always passes the threshold.
        [TestMethod]
        public void PolicyEngineEvaluatePreFilterShouldBlockWithoutConfidence()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 1f, AttackTypes.DoS, DetectionSource.PreFilter);
            var decision = engine.Evaluate(alert, CreatePolicy(source: DetectionSource.PreFilter));
            Assert.AreEqual(PolicyAction.Block, decision.Action);
            Assert.AreEqual("confidence_threshold_met", decision.Reason);
        }

        #endregion

        #region Detection Source Selection Tests

        // An Isolation Forest alert is judged against the IF threshold, not the RF one.
        [TestMethod]
        public void PolicyEngineEvaluateIsolationForestUsesIfThresholdOnly()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 0.99f, AttackTypes.DoS, DetectionSource.IsolationForest);
            var policy = CreatePolicy(rfThreshold: 0.6f, ifThreshold: 0.5f, source: DetectionSource.RandomForest);
            var decision = engine.Evaluate(alert, policy);
            Assert.AreEqual(PolicyAction.Block, decision.Action);
        }

        // A Random Forest alert is judged against the RF threshold.
        [TestMethod]
        public void PolicyEngineEvaluateRandomForestUsesRfThresholdOnly()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 0.4f, AttackTypes.DoS, DetectionSource.RandomForest);
            var policy = CreatePolicy(rfThreshold: 0.6f, ifThreshold: 0.1f, source: DetectionSource.IsolationForest);
            var decision = engine.Evaluate(alert, policy);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("confidence_below_threshold", decision.Reason);
        }

        // A null threshold means that detector is disabled: keep monitoring.
        [TestMethod]
        public void PolicyEngineEvaluateNullThresholdShouldMonitor()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest);
            var decision = engine.Evaluate(alert, CreatePolicy(rfThreshold: null));
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("confidence_below_threshold", decision.Reason);
        }

        #endregion

        #region Alert Match Criteria Tests

        // An empty criteria set matches every alert.
        [TestMethod]
        public void PolicyEngineEvaluateEmptyCriteriaShouldMatchAny()
        {
            var engine = CreateEngine();
            var decision = engine.Evaluate(CreateAlert(), CreatePolicy());
            Assert.AreEqual(PolicyAction.Block, decision.Action);
        }

        // A matching attack type lets the alert through.
        [TestMethod]
        public void PolicyEngineEvaluateMatchingAttackTypeShouldBlock()
        {
            var engine = CreateEngine();
            var policy = CreatePolicy();
            policy.MatchAttackTypes = AttackTypes.DoS;
            var decision = engine.Evaluate(CreateAlert(), policy);
            Assert.AreEqual(PolicyAction.Block, decision.Action);
        }

        // A different attack type is not acted on.
        [TestMethod]
        public void PolicyEngineEvaluateAttackTypeMismatchShouldMonitor()
        {
            var engine = CreateEngine();
            var policy = CreatePolicy();
            policy.MatchAttackTypes = AttackTypes.PortScan;
            var decision = engine.Evaluate(CreateAlert(), policy);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("no_match", decision.Reason);
        }

        // Comma separated attack types match any of the listed values.
        [TestMethod]
        public void PolicyEngineEvaluateMultipleAttackTypesShouldMatchAnyListed()
        {
            var engine = CreateEngine();
            var policy = CreatePolicy();
            policy.MatchAttackTypes = $"{AttackTypes.PortScan}, {AttackTypes.DoS}";
            var decision = engine.Evaluate(CreateAlert(), policy);
            Assert.AreEqual(PolicyAction.Block, decision.Action);
        }

        // A mismatched protocol is not acted on.
        [TestMethod]
        public void PolicyEngineEvaluateProtocolMismatchShouldMonitor()
        {
            var engine = CreateEngine();
            var policy = CreatePolicy();
            policy.MatchProtocol = ProtocolNumbers.Udp;
            var decision = engine.Evaluate(CreateAlert(), policy);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("no_match", decision.Reason);
        }

        // Every criterion must match for the policy to act.
        [TestMethod]
        public void PolicyEngineEvaluateAllCriteriaMatchShouldBlock()
        {
            var engine = CreateEngine();
            var policy = CreatePolicy();
            policy.MatchAttackTypes = AttackTypes.DoS;
            policy.MatchProtocol = ProtocolNumbers.Tcp;
            var decision = engine.Evaluate(CreateAlert(), policy);
            Assert.AreEqual(PolicyAction.Block, decision.Action);
        }

        // The alert 5-tuple is not a match condition: a different source IP still matches.
        [TestMethod]
        public void PolicyEngineEvaluateDifferentSourceIpShouldStillMatch()
        {
            var engine = CreateEngine();
            var policy = CreatePolicy();
            policy.MatchAttackTypes = AttackTypes.DoS;
            var alert = CreateAlert("203.0.113.77", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest);
            var decision = engine.Evaluate(alert, policy);
            Assert.AreEqual(PolicyAction.Block, decision.Action);
        }

        #endregion

        #region Allowlist Tests

        [TestMethod]
        public void PolicyEngineEvaluatePrivateIpShouldMonitor()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("192.168.1.100", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest);
            var decision = engine.Evaluate(alert, CreatePolicy());
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluateLocalhostShouldMonitor()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("127.0.0.1", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest);
            var decision = engine.Evaluate(alert, CreatePolicy());
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluateAllowlistIpShouldMonitor()
        {
            var engine = CreateEngine();
            var policy = CreatePolicy();
            policy.Allowlist = "8.8.8.8";
            var decision = engine.Evaluate(CreateAlert(), policy);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluatePublicIpShouldBlock()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest);
            var decision = engine.Evaluate(alert, CreatePolicy());
            Assert.AreEqual(PolicyAction.Block, decision.Action);
            Assert.IsNotNull(decision.Reason);
        }

        #endregion

        #region Cooldown Tests

        [TestMethod]
        public void PolicyEngineEvaluateSameIpTwiceShouldMonitorSecondBlock()
        {
            var engine = CreateEngine();
            var policy = CreatePolicy();
            var first = engine.Evaluate(CreateAlert(), policy);
            var second = engine.Evaluate(CreateAlert(), policy);
            Assert.AreEqual(PolicyAction.Block, first.Action);
            Assert.AreEqual(PolicyAction.Monitor, second.Action);
            Assert.AreEqual("cooldown", second.Reason);
        }

        [TestMethod]
        public void PolicyEngineEvaluateAfterCooldownShouldBlockAgain()
        {
            var clock = new FakeTimeProvider();
            var engine = CreateEngine(clock);
            var policy = CreatePolicy();

            var first = engine.Evaluate(CreateAlert(), policy);
            clock.Advance(TimeSpan.FromSeconds(60));
            var second = engine.Evaluate(CreateAlert(), policy);

            Assert.AreEqual(PolicyAction.Block, first.Action);
            Assert.AreEqual(PolicyAction.Block, second.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluateDifferentIpsShouldBlockBoth()
        {
            var engine = CreateEngine();
            var policy = CreatePolicy();
            var first = engine.Evaluate(CreateAlert("8.8.8.8", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest), policy);
            var second = engine.Evaluate(CreateAlert("1.1.1.1", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest), policy);
            Assert.AreEqual(PolicyAction.Block, first.Action);
            Assert.AreEqual(PolicyAction.Block, second.Action);
        }

        #endregion

        #region Decision Result Tests

        [TestMethod]
        public void PolicyEngineEvaluateShouldCopySourceIpAndAttackType()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 0.70f, AttackTypes.BruteForce, DetectionSource.RandomForest);
            var decision = engine.Evaluate(alert, CreatePolicy(0.6f));
            Assert.AreEqual(alert.SourceIp, decision.SourceIp);
            Assert.AreEqual(alert.AttackType, decision.AttackType);
            Assert.AreEqual(alert.Confidence, decision.Confidence);
        }

        [TestMethod]
        public void PolicyEngineEvaluateShouldGenerateAlertId()
        {
            var engine = CreateEngine();
            var policy = CreatePolicy();
            var first = engine.Evaluate(CreateAlert(), policy);
            var second = engine.Evaluate(CreateAlert("1.1.1.1", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest), policy);
            Assert.IsFalse(string.IsNullOrEmpty(first.Id));
            Assert.AreNotEqual(first.Id, second.Id);
        }

        // The engine writes the decision onto the alert, not the policy.
        [TestMethod]
        public void PolicyEngineEvaluateShouldRecordDecisionOnAlert()
        {
            var engine = CreateEngine();
            var policy = CreatePolicy();
            var alert = CreateAlert();
            var decision = engine.Evaluate(alert, policy);
            Assert.AreEqual(PolicyAction.Block, decision.Action);
            Assert.AreEqual(AttackTypes.DoS, decision.AttackType);
            Assert.IsFalse(string.IsNullOrEmpty(decision.Id));
        }

        #endregion

        #region Helper Methods

        private static PolicyEngine CreateEngine()
        {
            return CreateEngine(TimeProvider.System);
        }

        private static PolicyEngine CreateEngine(TimeProvider clock)
        {
            return new PolicyEngine(clock, NullLogger<PolicyEngine>.Instance);
        }

        // Default policy: RF enabled at 0.6, IF enabled at 0.6, 60 s cooldown.
        private static Policy CreatePolicy(
            float? rfThreshold = 0.6f,
            float? ifThreshold = 0.6f,
            DetectionSource source = DetectionSource.RandomForest)
        {
            return new Policy
            {
                Id = "P-1",
                DetectionSource = source,
                RfConfidenceThreshold = rfThreshold,
                IfConfidenceThreshold = ifThreshold,
                BlockDurationMinutes = 60,
                DecisionCooldownSeconds = 60
            };
        }

        private static Alert CreateAlert()
        {
            return CreateAlert("8.8.8.8", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest);
        }

        private static Alert CreateAlert(string sourceIp, float confidence, string attackType, DetectionSource source)
        {
            return new Alert
            {
                SourceIp = sourceIp,
                SourcePort = 12345,
                DestinationIp = "192.168.1.10",
                DestinationPort = 80,
                Protocol = ProtocolNumbers.Tcp,
                Confidence = confidence,
                AttackType = attackType,
                Source = source,
                Reason = string.Empty
            };
        }

        #endregion
    }
}

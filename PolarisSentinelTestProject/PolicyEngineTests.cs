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
            Assert.AreEqual("below_threshold", decision.Reason);
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

        // 空阈值不自动封禁。
        // A blank threshold prevents automatic blocking.
        [TestMethod]
        public void PolicyEngineEvaluateNullRfThresholdShouldMonitor()
        {
            var engine = CreateEngine();
            var decision = engine.Evaluate(CreateAlert(), CreatePolicy(rfThreshold: null));
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("threshold_disabled", decision.Reason);
        }

        // Isolation Forest detections use the IF threshold, not the RF one.
        [TestMethod]
        public void PolicyEngineEvaluateIsolationForestUsesIfThreshold()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 0.70f, AttackTypes.DoS, DetectionSource.IsolationForest);
            var policy = CreatePolicy(rfThreshold: 0.9f, ifThreshold: 0.6f, source: DetectionSource.IsolationForest);
            var decision = engine.Evaluate(alert, policy);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("unknown_anomaly_monitor_only", decision.Reason);
        }

        // 低于阈值只监控。
        // Monitor results below the threshold.
        [TestMethod]
        public void PolicyEngineEvaluateIsolationForestBelowIfThresholdShouldMonitor()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 0.50f, AttackTypes.DoS, DetectionSource.IsolationForest);
            var policy = CreatePolicy(rfThreshold: 0.6f, ifThreshold: 0.7f, source: DetectionSource.IsolationForest);
            var decision = engine.Evaluate(alert, policy);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("below_threshold", decision.Reason);
        }

        // A pre-filter verdict blocks immediately.
        [TestMethod]
        public void PolicyEngineEvaluatePreFilterShouldBlockImmediately()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 1f, AttackTypes.DoS, DetectionSource.PreFilter);
            var decision = engine.Evaluate(alert, CreatePolicy(source: DetectionSource.PreFilter));
            Assert.AreEqual(PolicyAction.Block, decision.Action);
            Assert.AreEqual("attack_detected", decision.Reason);
        }

        #endregion

        #region Detection Source Selection Tests

        // 检测来源必须一致。
        // The detection source must match.
        [TestMethod]
        public void PolicyEngineEvaluateDifferentSourceShouldMonitor()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 0.99f, AttackTypes.DoS, DetectionSource.IsolationForest);
            var policy = CreatePolicy(rfThreshold: 0.6f, ifThreshold: 0.5f, source: DetectionSource.RandomForest);
            var decision = engine.Evaluate(alert, policy);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("no_match", decision.Reason);
        }

        // RF 结果不能套用 IF 策略。
        // Do not apply an IF policy to an RF result.
        [TestMethod]
        public void PolicyEngineEvaluateRandomForestWithIfPolicyShouldMonitor()
        {
            var engine = CreateEngine();
            var alert = CreateAlert("8.8.8.8", 0.4f, AttackTypes.DoS, DetectionSource.RandomForest);
            var policy = CreatePolicy(rfThreshold: 0.6f, ifThreshold: 0.1f, source: DetectionSource.IsolationForest);
            var decision = engine.Evaluate(alert, policy);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("no_match", decision.Reason);
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

        [TestMethod]
        [DataRow(0.59f, PolicyAction.Monitor)]
        [DataRow(0.60f, PolicyAction.Block)]
        [DataRow(0.79f, PolicyAction.Block)]
        [DataRow(0.80f, PolicyAction.Block)]
        public void PolicyThresholdBoundary(float confidence, PolicyAction expected)
        {
            var result = CreateEngine().Evaluate(CreateAlert("203.0.113.66", confidence,
                AttackTypes.DoS, DetectionSource.RandomForest), CreatePolicy());
            Assert.AreEqual(expected, result.Action);
        }

        [TestMethod]
        [DataRow("127.0.0.1")]
        [DataRow("10.1.2.3")]
        [DataRow("172.16.1.1")]
        [DataRow("192.168.1.5")]
        [DataRow("169.254.1.2")]
        [DataRow("224.0.0.1")]
        [DataRow("255.255.255.255")]
        [DataRow("::1")]
        [DataRow("fe80::1")]
        [DataRow("fc00::1")]
        [DataRow("ff02::1")]
        [DataRow("::ffff:192.168.1.5")]
        public void AllowlistedSourceShouldMonitor(string ip)
        {
            var result = CreateEngine().Evaluate(CreateAlert(ip, 0.99f,
                AttackTypes.DoS, DetectionSource.RandomForest), CreatePolicy());
            Assert.AreEqual(PolicyAction.Monitor, result.Action);
            Assert.AreEqual("allowlisted_source", result.Reason);
        }

        [TestMethod]
        public void ConfiguredIpAndCidrShouldMonitor()
        {
            var engine = new PolicyEngine(TimeProvider.System, NullLogger<PolicyEngine>.Instance,
                new[] { "203.0.113.0/24", "198.51.100.8" });
            foreach (var ip in new[] { "203.0.113.66", "198.51.100.8" })
                Assert.AreEqual(PolicyAction.Monitor, engine.Evaluate(CreateAlert(ip, 0.99f,
                    AttackTypes.DoS, DetectionSource.RandomForest), CreatePolicy()).Action);
        }

        [TestMethod]
        public void DisabledPolicyShouldMonitor()
        {
            var policy = CreatePolicy();
            policy.Enabled = false;
            Assert.AreEqual("policy_disabled", CreateEngine().Evaluate(CreateAlert(), policy).Reason);
        }

        [TestMethod]
        public void SourceWildcardShouldNotBypassAllowlist()
        {
            var policy = CreatePolicy();
            policy.RuleSourceIpAction = PolicyAction.Allow;
            var result = CreateEngine().Evaluate(CreateAlert(), policy);
            Assert.AreEqual(PolicyAction.Monitor, result.Action);
            Assert.AreEqual("source_ip_not_restricted", result.Reason);
        }

        #region Helper Methods

        private static PolicyEngine CreateEngine()
        {
            return CreateEngine(TimeProvider.System);
        }

        private static PolicyEngine CreateEngine(TimeProvider clock)
        {
            return new PolicyEngine(clock, NullLogger<PolicyEngine>.Instance);
        }

        // Default policy: any attack type, any protocol.
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
                BlockDurationMinutes = 60
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

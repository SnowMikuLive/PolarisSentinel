using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
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
            var detection = CreateDetectionResult();
            var decision = engine.Evaluate(detection);
            Assert.IsNotNull(decision);
            Assert.IsTrue(Enum.IsDefined(typeof(PolicyAction), decision.Action));
            engine.RefreshSettingsAsync().GetAwaiter().GetResult();
        }

        [TestMethod]
        public void PolicyEngineEvaluateBenignTrafficShouldIgnore()
        {
            var engine = CreateEngine();
            var detection = CreateDetectionResult("8.8.8.8", 0.99f, AttackTypes.Benign, DetectionSource.RandomForest);
            var decision = engine.Evaluate(detection);
            Assert.AreEqual(PolicyAction.Ignore, decision.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluateHighConfidenceAttackShouldBlock()
        {
            var engine = CreateEngine();
            var detection = CreateDetectionResult();
            var decision = engine.Evaluate(detection);
            Assert.AreEqual(PolicyAction.Block, decision.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluateLowConfidenceShouldIgnore()
        {
            var engine = CreateEngine();
            var detection = CreateDetectionResult("8.8.8.8", 0.50f, AttackTypes.DoS, DetectionSource.RandomForest);
            var decision = engine.Evaluate(detection);
            Assert.AreEqual(PolicyAction.Ignore, decision.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluateMediumConfidenceShouldMonitor()
        {
            var engine = CreateEngine();
            var detection = CreateDetectionResult("8.8.8.8", 0.70f, AttackTypes.DoS, DetectionSource.RandomForest);
            var decision = engine.Evaluate(detection);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluateUnknownAnomalyShouldMonitor()
        {
            var engine = CreateEngine();
            var detection = CreateDetectionResult("8.8.8.8", 0.99f, AttackTypes.UnknownAnomaly, DetectionSource.IsolationForest);
            var decision = engine.Evaluate(detection);
            //未知异常永不自动Block
            //Unknown anomalies are never auto-blocked
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreNotEqual(PolicyAction.Block, decision.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluateNoDetectionSourceShouldIgnore()
        {
            var engine = CreateEngine();
            var detection = CreateDetectionResult("8.8.8.8", 0.99f, AttackTypes.DoS, DetectionSource.None);
            var decision = engine.Evaluate(detection);
            Assert.AreEqual(PolicyAction.Ignore, decision.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluatePortScanShouldBlockWhenConfidenceIsHigh()
        {
            var engine = CreateEngine();
            var detection = CreateDetectionResult("1.1.1.1", 0.95f, AttackTypes.PortScan, DetectionSource.RandomForest);
            var decision = engine.Evaluate(detection);
            Assert.AreEqual(PolicyAction.Block, decision.Action);
        }

        #endregion

        #region Allowlist Tests

        //内网/白名单命中时Block降级为Monitor
        //Block downgraded to Monitor for protected addresses

        [TestMethod]
        public void PolicyEngineEvaluatePrivateIpShouldMonitor()
        {
            var engine = CreateEngine();
            var detection = CreateDetectionResult("192.168.1.100", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest);
            var decision = engine.Evaluate(detection);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluateLocalhostShouldMonitor()
        {
            var engine = CreateEngine();
            var detection = CreateDetectionResult("127.0.0.1", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest);
            var decision = engine.Evaluate(detection);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluateAllowlistIpShouldMonitor()
        {
            var settings = new UserSettings();
            settings.Allowlist = "8.8.8.8";
            var engine = CreateEngine(settings);
            var detection = CreateDetectionResult();
            var decision = engine.Evaluate(detection);
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluatePublicIpShouldBlock()
        {
            var engine = CreateEngine();
            var detection = CreateDetectionResult("8.8.8.8", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest);
            var decision = engine.Evaluate(detection);
            Assert.AreEqual(PolicyAction.Block, decision.Action);
            Assert.IsNotNull(decision.Reason);
        }

        #endregion

        #region Cooldown Tests

        //冷却期内同IP重复Block被抑制
        //Repeated Block for same IP is suppressed within cooldown

        [TestMethod]
        public void PolicyEngineEvaluateSameIpTwiceShouldIgnoreSecondBlock()
        {
            var engine = CreateEngine();
            // 每次传入新实例；Evaluate 会就地写入决策字段
            // Pass a fresh instance each time; Evaluate writes decision fields in place
            var first = engine.Evaluate(CreateDetectionResult());
            var second = engine.Evaluate(CreateDetectionResult());
            Assert.AreEqual(PolicyAction.Block, first.Action);
            Assert.AreEqual(PolicyAction.Ignore, second.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluateAfterCooldownShouldBlockAgain()
        {
            var clock = new FakeTimeProvider();
<<<<<<< HEAD
            var engine = CreateEngine(new Policy { Name = string.Empty }, clock);
            var detection = CreateDetectionResult();
            var first = engine.Evaluate(detection);
            //冷却期满（60s）后可再次Block
            //Block allowed again after cooldown expires
=======
            var engine = CreateEngine(new UserSettings(), clock);
            var first = engine.Evaluate(CreateDetectionResult());
            // 冷却期满（60s）后可再次 Block
            // Block allowed again after cooldown expires
>>>>>>> d47e7ec0c32803f010bc8a3c97a4dc42d392cd92
            clock.Advance(TimeSpan.FromSeconds(60));
            var second = engine.Evaluate(CreateDetectionResult());
            Assert.AreEqual(PolicyAction.Block, first.Action);
            Assert.AreEqual(PolicyAction.Block, second.Action);
        }

        [TestMethod]
        public void PolicyEngineEvaluateDifferentIpsShouldBlockBoth()
        {
            var engine = CreateEngine();
            var first = engine.Evaluate(CreateDetectionResult("8.8.8.8", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest));
            var second = engine.Evaluate(CreateDetectionResult("1.1.1.1", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest));
            Assert.AreEqual(PolicyAction.Block, first.Action);
            Assert.AreEqual(PolicyAction.Block, second.Action);
        }

        #endregion

        #region Config Tests

        [TestMethod]
        public void PolicyEngineEvaluateAfterThresholdChangeShouldUseNewValue()
        {
            var settings = new UserSettings();
            var engine = CreateEngine(settings);
            var before = engine.Evaluate(CreateDetectionResult("8.8.8.8", 0.65f, AttackTypes.DoS, DetectionSource.RandomForest));
            Assert.AreEqual(PolicyAction.Monitor, before.Action);

            //修改阈值后下一次Evaluate立即生效
            //Next Evaluate uses updated threshold immediately
            settings.RfConfidenceThreshold = 0.9f;
            var after = engine.Evaluate(CreateDetectionResult("8.8.8.8", 0.65f, AttackTypes.DoS, DetectionSource.RandomForest));
            Assert.AreEqual(PolicyAction.Ignore, after.Action);
        }

        #endregion

        #region Decision Result Tests

        [TestMethod]
        public void PolicyEngineEvaluateShouldCopySourceIpAndAttackType()
        {
            var engine = CreateEngine();
            var detection = CreateDetectionResult("8.8.8.8", 0.70f, AttackTypes.BruteForce, DetectionSource.RandomForest);
            var decision = engine.Evaluate(detection);
            Assert.AreEqual(detection.SourceIp, decision.SourceIp);
            Assert.AreEqual(detection.AttackType, decision.AttackType);
            Assert.AreEqual(detection.Confidence, decision.Confidence);
        }

        [TestMethod]
        public void PolicyEngineEvaluateShouldGenerateAlertId()
        {
            var engine = CreateEngine();
            // 每次传入新实例；Evaluate 会就地写入告警编号
            // Pass a fresh instance each time; Evaluate writes the alert id in place
            var first = engine.Evaluate(CreateDetectionResult("8.8.8.8", 0.70f, AttackTypes.DoS, DetectionSource.RandomForest));
            var second = engine.Evaluate(CreateDetectionResult("8.8.8.8", 0.70f, AttackTypes.DoS, DetectionSource.RandomForest));
            Assert.IsFalse(string.IsNullOrEmpty(first.Id));
            Assert.AreNotEqual(first.Id, second.Id);
        }

        #endregion

        #region Helper Methods

        private PolicyEngine CreateEngine()
        {
            return CreateEngine(new UserSettings(), TimeProvider.System);
        }

        private PolicyEngine CreateEngine(UserSettings settings)
        {
            return CreateEngine(settings, TimeProvider.System);
        }

        private PolicyEngine CreateEngine(UserSettings settings, TimeProvider clock)
        {
            return new PolicyEngine(() => settings, clock, NullLogger<PolicyEngine>.Instance);
        }

        //默认公网高置信DoS
        //Default high-confidence DoS from public IP
        private Alert CreateDetectionResult()
        {
            return CreateDetectionResult("8.8.8.8", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest);
        }

        private Alert CreateDetectionResult(string sourceIp, float confidence, string attackType, DetectionSource source)
        {
            return new Alert
            {
                SourceIp = sourceIp,
                DestinationIp = "192.168.1.10",
                Confidence = confidence,
                AttackType = attackType,
                Source = source,
                Reason = string.Empty
            };
        }

        #endregion
    }
}

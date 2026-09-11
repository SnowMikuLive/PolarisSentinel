using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
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
        public void PolicyEngine_Evaluate_ShouldReturnADecision()
        {
            // Arrange
            var engine = CreateEngine();
            var detection = CreateDetectionResult();

            // Act
            var decision = engine.Evaluate(detection);

            // Assert
            Assert.IsNotNull(decision);
            Assert.IsNotNull(decision.Action);
            engine.RefreshSettingsAsync().GetAwaiter().GetResult();
        }

        [TestMethod]
        public void PolicyEngine_Evaluate_BenignTraffic_ShouldIgnore()
        {
            // Arrange
            var engine = CreateEngine();
            var detection = CreateDetectionResult("8.8.8.8", 0.99f, AttackTypes.Benign, DetectionSource.RandomForest);

            // Act
            var decision = engine.Evaluate(detection);

            // Assert
            Assert.AreEqual(PolicyAction.Ignore, decision.Action);
        }

        [TestMethod]
        public void PolicyEngine_Evaluate_HighConfidenceAttack_ShouldBlock()
        {
            // Arrange
            var engine = CreateEngine();
            var detection = CreateDetectionResult();

            // Act
            var decision = engine.Evaluate(detection);

            // Assert
            Assert.AreEqual(PolicyAction.Block, decision.Action);
        }

        [TestMethod]
        public void PolicyDecision_Properties_ShouldBeSetCorrectly()
        {
            // Arrange
            var decidedAt = DateTime.UtcNow;
            var decision = new PolicyDecision
            {
                AlertId = Guid.NewGuid(),
                Action = PolicyAction.Monitor,
                SourceIp = "192.168.1.100",
                AttackType = AttackTypes.DoS,
                Confidence = 0.7f,
                DecidedAt = decidedAt,
                Reason = "test"
            };

            // Assert
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreEqual("192.168.1.100", decision.SourceIp);
            Assert.AreEqual(AttackTypes.DoS, decision.AttackType);
            Assert.AreEqual(0.7f, decision.Confidence);
            Assert.AreEqual(decidedAt, decision.DecidedAt);
            Assert.AreEqual("test", decision.Reason);
        }

        #endregion

        #region Threshold Tests

        [TestMethod]
        public void PolicyEngine_Evaluate_LowConfidence_ShouldIgnore()
        {
            // Arrange
            var engine = CreateEngine();
            var detection = CreateDetectionResult("8.8.8.8", 0.50f, AttackTypes.DoS, DetectionSource.RandomForest);

            // Act
            var decision = engine.Evaluate(detection);

            // Assert
            Assert.AreEqual(PolicyAction.Ignore, decision.Action);
        }

        [TestMethod]
        public void PolicyEngine_Evaluate_MediumConfidence_ShouldMonitor()
        {
            // Arrange
            var engine = CreateEngine();
            var detection = CreateDetectionResult("8.8.8.8", 0.70f, AttackTypes.DoS, DetectionSource.RandomForest);

            // Act
            var decision = engine.Evaluate(detection);

            // Assert
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
        }

        [TestMethod]
        public void PolicyEngine_Evaluate_UnknownAnomaly_ShouldMonitor()
        {
            // Arrange
            var engine = CreateEngine();
            var detection = CreateDetectionResult("8.8.8.8", 0.99f, AttackTypes.UnknownAnomaly, DetectionSource.IsolationForest);

            // Act
            var decision = engine.Evaluate(detection);

            // Assert
            // 未知异常永不自动 Block
            // Unknown anomalies are never auto-blocked
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.AreNotEqual(PolicyAction.Block, decision.Action);
        }

        [TestMethod]
        public void PolicyEngine_Evaluate_NoDetectionSource_ShouldIgnore()
        {
            // Arrange
            var engine = CreateEngine();
            var detection = CreateDetectionResult("8.8.8.8", 0.99f, AttackTypes.DoS, DetectionSource.None);

            // Act
            var decision = engine.Evaluate(detection);

            // Assert
            Assert.AreEqual(PolicyAction.Ignore, decision.Action);
        }

        [TestMethod]
        public void PolicyEngine_Evaluate_PortScan_ShouldBlockWhenConfidenceIsHigh()
        {
            // Arrange
            var engine = CreateEngine();
            var detection = CreateDetectionResult("1.1.1.1", 0.95f, AttackTypes.PortScan, DetectionSource.RandomForest);

            // Act
            var decision = engine.Evaluate(detection);

            // Assert
            Assert.AreEqual(PolicyAction.Block, decision.Action);
        }

        #endregion

        #region Allowlist Tests

        // 内网/白名单命中时 Block 降级为 Monitor
        // Block downgraded to Monitor for protected addresses

        [TestMethod]
        public void PolicyEngine_Evaluate_PrivateIp_ShouldMonitor()
        {
            // Arrange
            var engine = CreateEngine();
            var detection = CreateDetectionResult("192.168.1.100", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest);

            // Act
            var decision = engine.Evaluate(detection);

            // Assert
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
        }

        [TestMethod]
        public void PolicyEngine_Evaluate_Localhost_ShouldMonitor()
        {
            // Arrange
            var engine = CreateEngine();
            var detection = CreateDetectionResult("127.0.0.1", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest);

            // Act
            var decision = engine.Evaluate(detection);

            // Assert
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
        }

        [TestMethod]
        public void PolicyEngine_Evaluate_AllowlistIp_ShouldMonitor()
        {
            // Arrange
            var settings = new PolicySettings();
            settings.Allowlist = new string[] { "8.8.8.8" };
            var engine = CreateEngine(settings);
            var detection = CreateDetectionResult();

            // Act
            var decision = engine.Evaluate(detection);

            // Assert
            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
        }

        [TestMethod]
        public void PolicyEngine_Evaluate_PublicIp_ShouldBlock()
        {
            // Arrange
            var engine = CreateEngine();
            var detection = CreateDetectionResult("8.8.8.8", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest);

            // Act
            var decision = engine.Evaluate(detection);

            // Assert
            Assert.AreEqual(PolicyAction.Block, decision.Action);
            Assert.IsNotNull(decision.Reason);
        }

        #endregion

        #region Cooldown Tests

        // 冷却期内同 IP 重复 Block 被抑制
        // Repeated Block for same IP is suppressed within cooldown

        [TestMethod]
        public void PolicyEngine_Evaluate_SameIpTwice_ShouldIgnoreSecondBlock()
        {
            // Arrange
            var engine = CreateEngine();
            var detection = CreateDetectionResult();

            // Act
            var first = engine.Evaluate(detection);
            var second = engine.Evaluate(detection);

            // Assert
            Assert.AreEqual(PolicyAction.Block, first.Action);
            Assert.AreEqual(PolicyAction.Ignore, second.Action);
        }

        [TestMethod]
        public void PolicyEngine_Evaluate_AfterCooldown_ShouldBlockAgain()
        {
            // Arrange
            var clock = new FakeTimeProvider();
            var engine = CreateEngine(new PolicySettings(), clock);
            var detection = CreateDetectionResult();

            // Act
            var first = engine.Evaluate(detection);
            // 冷却期满（60s）后可再次 Block
            // Block allowed again after cooldown expires
            clock.Advance(TimeSpan.FromSeconds(60));
            var second = engine.Evaluate(detection);

            // Assert
            Assert.AreEqual(PolicyAction.Block, first.Action);
            Assert.AreEqual(PolicyAction.Block, second.Action);
        }

        [TestMethod]
        public void PolicyEngine_Evaluate_DifferentIps_ShouldBlockBoth()
        {
            // Arrange
            var engine = CreateEngine();

            // Act
            var first = engine.Evaluate(CreateDetectionResult("8.8.8.8", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest));
            var second = engine.Evaluate(CreateDetectionResult("1.1.1.1", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest));

            // Assert
            Assert.AreEqual(PolicyAction.Block, first.Action);
            Assert.AreEqual(PolicyAction.Block, second.Action);
        }

        [TestMethod]
        public void PolicyEngine_RefreshSettingsAsync_ShouldNotThrow()
        {
            // Arrange
            var engine = CreateEngine();

            // Act & Assert
            try
            {
                engine.RefreshSettingsAsync().GetAwaiter().GetResult();
                Assert.IsTrue(true);
            }
            catch (Exception ex)
            {
                Assert.Fail($"RefreshSettingsAsync threw exception: {ex.Message}");
            }
        }

        #endregion

        #region Config Tests

        [TestMethod]
        public void PolicyEngine_Evaluate_AfterThresholdChange_ShouldUseNewValue()
        {
            // Arrange
            var settings = new PolicySettings();
            var engine = CreateEngine(settings);
            var detection = CreateDetectionResult("8.8.8.8", 0.65f, AttackTypes.DoS, DetectionSource.RandomForest);

            var before = engine.Evaluate(detection);
            Assert.AreEqual(PolicyAction.Monitor, before.Action);

            // 修改阈值后下一次 Evaluate 立即生效
            // Next Evaluate uses updated threshold immediately
            settings.RfConfidenceThreshold = 0.9;

            // Act
            var after = engine.Evaluate(detection);

            // Assert
            Assert.AreEqual(PolicyAction.Ignore, after.Action);
        }

        #endregion

        #region Decision Result Tests

        [TestMethod]
        public void PolicyEngine_Evaluate_ShouldCopySourceIpAndAttackType()
        {
            // Arrange
            var engine = CreateEngine();
            var detection = CreateDetectionResult("8.8.8.8", 0.70f, AttackTypes.BruteForce, DetectionSource.RandomForest);

            // Act
            var decision = engine.Evaluate(detection);

            // Assert
            Assert.AreEqual(detection.SourceIp, decision.SourceIp);
            Assert.AreEqual(detection.AttackType, decision.AttackType);
            Assert.AreEqual(detection.Confidence, decision.Confidence);
        }

        [TestMethod]
        public void PolicyEngine_Evaluate_ShouldGenerateAlertId()
        {
            // Arrange
            var engine = CreateEngine();
            var detection = CreateDetectionResult("8.8.8.8", 0.70f, AttackTypes.DoS, DetectionSource.RandomForest);

            // Act
            var first = engine.Evaluate(detection);
            var second = engine.Evaluate(detection);

            // Assert
            Assert.AreNotEqual(Guid.Empty, first.AlertId);
            Assert.AreNotEqual(first.AlertId, second.AlertId);
        }

        [TestMethod]
        public void PolicyEngine_Evaluate_ShouldNotThrow()
        {
            // Arrange
            var engine = CreateEngine();
            var detection = CreateDetectionResult();

            // Act & Assert
            try
            {
                engine.Evaluate(detection);
                Assert.IsTrue(true);
            }
            catch (Exception ex)
            {
                Assert.Fail($"Evaluate threw exception: {ex.Message}");
            }
        }

        #endregion

        #region Helper Methods

        private PolicyEngine CreateEngine()
        {
            return CreateEngine(new PolicySettings(), TimeProvider.System);
        }

        private PolicyEngine CreateEngine(PolicySettings settings)
        {
            return CreateEngine(settings, TimeProvider.System);
        }

        private PolicyEngine CreateEngine(PolicySettings settings, TimeProvider clock)
        {
            var monitor = new SimpleOptionsMonitor(settings);
            return new PolicyEngine(monitor, clock, NullLogger<PolicyEngine>.Instance);
        }

        // 默认公网高置信 DoS
        // Default high-confidence DoS from public IP
        private DetectionResult CreateDetectionResult()
        {
            return CreateDetectionResult("8.8.8.8", 0.99f, AttackTypes.DoS, DetectionSource.RandomForest);
        }

        private DetectionResult CreateDetectionResult(string sourceIp, float confidence, string attackType, DetectionSource source)
        {
            return new DetectionResult
            {
                SourceIp = sourceIp,
                Confidence = confidence,
                AttackType = attackType,
                Source = source
            };
        }

        // 测试用 IOptionsMonitor，无需启动 Web 宿主
        // Test IOptionsMonitor without starting the web host
        private class SimpleOptionsMonitor : IOptionsMonitor<PolicySettings>
        {
            public PolicySettings CurrentValue { get; set; }

            public SimpleOptionsMonitor(PolicySettings value)
            {
                CurrentValue = value;
            }

            public PolicySettings Get(string? name)
            {
                return CurrentValue;
            }

            public IDisposable OnChange(Action<PolicySettings, string?> listener)
            {
                return null!;
            }
        }

        #endregion
    }
}

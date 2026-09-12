using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;
using PolarisSentinel.FirewallEnforement;
using System;
using System.Linq;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class FirewallEnforcerUnitTest
    {
        #region Block Rule Tests

        [TestMethod]
        public void FirewallEnforcer_DefaultDryRun_ShouldStoreRuleInMemory()
        {
            // Arrange
            var engine = CreateEngine(CreateClock());

            // Act
            engine.BlockIp(CreateDecision(), TimeSpan.FromMinutes(60));

            // Assert
            Assert.IsTrue(engine.IsDryRun);
            Assert.HasCount(1, engine.GetAllRules());
        }

        [TestMethod]
        public void FirewallEnforcer_BlockIp_ShouldSaveRuleDetails()
        {
            // Arrange
            var clock = CreateClock();
            var engine = CreateEngine(clock);
            var decision = CreateDecision();
            var createdAt = clock.GetUtcNow();

            // Act
            engine.BlockIp(decision, TimeSpan.FromMinutes(60));
            var rule = engine.GetAllRules().Single();

            // Assert
            Assert.AreEqual(FirewallRuleNaming.BuildRuleName(decision.AlertId), rule.Name);
            Assert.AreEqual(decision.SourceIp, rule.RemoteAddress);
            Assert.IsTrue(rule.Enabled);
            Assert.IsTrue(rule.IsBlockRule);
            Assert.AreEqual(decision.AlertId, rule.AlertId);
            Assert.AreEqual(decision.AttackType, rule.AttackType);
            Assert.AreEqual(createdAt, rule.CreatedAt);
            Assert.AreEqual(createdAt.AddMinutes(60), rule.ExpiresAt);
        }

        // 同 IP 复用规则，只延长过期时间
        // Reuse rule for same IP; extend expiry only
        [TestMethod]
        public void FirewallEnforcer_SameIp_ShouldExtendExpiryWithoutAddingRule()
        {
            // Arrange
            var clock = CreateClock();
            var engine = CreateEngine(clock);
            var decision = CreateDecision();
            var createdAt = clock.GetUtcNow();
            engine.BlockIp(decision, TimeSpan.FromMinutes(60));

            // Act
            clock.Advance(TimeSpan.FromMinutes(5));
            engine.BlockIp(CreateDecision(), TimeSpan.FromMinutes(60));
            var rules = engine.GetAllRules().ToList();

            // Assert
            Assert.HasCount(1, rules);
            Assert.AreEqual(FirewallRuleNaming.BuildRuleName(decision.AlertId), rules[0].Name);
            Assert.AreEqual(createdAt, rules[0].CreatedAt);
            Assert.AreEqual(createdAt.AddMinutes(65), rules[0].ExpiresAt);
        }

        #endregion

        #region Validation Tests

        // 非 Block 或无效 IP 不创建规则
        // Non-Block or invalid IP requests do not create rules

        [TestMethod]
        public void FirewallEnforcer_Monitor_ShouldNotCreateRule()
        {
            // Arrange
            var engine = CreateEngine(CreateClock());
            var decision = CreateDecision(action: PolicyAction.Monitor);

            // Act
            engine.BlockIp(decision, TimeSpan.FromMinutes(60));

            // Assert
            Assert.IsEmpty(engine.GetAllRules());
        }

        [TestMethod]
        public void FirewallEnforcer_InvalidIp_ShouldNotCreateRule()
        {
            // Arrange
            var engine = CreateEngine(CreateClock());
            var decision = CreateDecision("bad-ip");

            // Act
            engine.BlockIp(decision, TimeSpan.FromMinutes(60));

            // Assert
            Assert.IsEmpty(engine.GetAllRules());
        }

        #endregion

        #region Rule Removal Tests

        [TestMethod]
        public void FirewallEnforcer_RemoveRule_ShouldDeleteCreatedRule()
        {
            // Arrange
            var engine = CreateEngine(CreateClock());
            var decision = CreateDecision();
            engine.BlockIp(decision, TimeSpan.FromMinutes(60));
            var rule = engine.GetAllRules().Single();

            // Act
            engine.RemoveRule(rule.Name);

            // Assert
            Assert.IsEmpty(engine.GetAllRules());
        }

        [TestMethod]
        public void FirewallEnforcer_RemoveOtherName_ShouldKeepCreatedRule()
        {
            // Arrange
            var engine = CreateEngine(CreateClock());
            var decision = CreateDecision();
            engine.BlockIp(decision, TimeSpan.FromMinutes(60));

            // Act
            engine.RemoveRule("OtherApplication_Rule");
            var rules = engine.GetAllRules().ToList();

            // Assert
            Assert.HasCount(1, rules);
            Assert.AreEqual(FirewallRuleNaming.BuildRuleName(decision.AlertId), rules[0].Name);
        }

        // 仅删除已过期规则
        // Remove only expired rules
        [TestMethod]
        public void FirewallEnforcer_RemoveExpired_ShouldKeepActiveRule()
        {
            // Arrange
            var clock = CreateClock();
            var engine = CreateEngine(clock);
            engine.BlockIp(CreateDecision("203.0.113.66"), TimeSpan.FromMinutes(60));
            engine.BlockIp(CreateDecision("198.51.100.66"), TimeSpan.FromMinutes(120));

            // Act
            clock.Advance(TimeSpan.FromMinutes(60));
            int removed = engine.RemoveExpiredRules();
            var rules = engine.GetAllRules().ToList();

            // Assert
            Assert.AreEqual(1, removed);
            Assert.HasCount(1, rules);
            Assert.AreEqual("198.51.100.66", rules[0].RemoteAddress);
        }

        [TestMethod]
        public void FirewallEnforcer_RemoveAll_ShouldDeleteCreatedRules()
        {
            // Arrange
            var engine = CreateEngine(CreateClock());
            engine.BlockIp(CreateDecision("203.0.113.66"), TimeSpan.FromMinutes(60));
            engine.BlockIp(CreateDecision("198.51.100.66"), TimeSpan.FromMinutes(60));

            // Act
            int removed = engine.RemoveAllManagedRules();

            // Assert
            Assert.AreEqual(2, removed);
            Assert.IsEmpty(engine.GetAllRules());
        }

        #endregion

        #region Helper Methods

        // 默认 DryRun，测试只操作内存规则
        // Default DryRun keeps test rules in memory
        private WindowsFirewallEnforcer CreateEngine(FakeTimeProvider clock)
        {
            var options = Options.Create(new FirewallOptions());
            return new WindowsFirewallEnforcer(
                options, clock, NullLogger<WindowsFirewallEnforcer>.Instance);
        }

        private FakeTimeProvider CreateClock()
        {
            return new FakeTimeProvider(new DateTimeOffset(2026, 9, 12, 0, 0, 0, TimeSpan.Zero));
        }

        // 默认使用 RFC 5737 文档地址
        // Default uses RFC 5737 documentation addresses
        private PolicyDecision CreateDecision(string ip = "203.0.113.66", PolicyAction action = PolicyAction.Block)
        {
            return new PolicyDecision
            {
                AlertId = Guid.NewGuid(),
                Action = action,
                SourceIp = ip,
                AttackType = AttackTypes.DoS,
                Confidence = 0.95f,
                DecidedAt = new DateTime(2026, 9, 12, 0, 0, 0, DateTimeKind.Utc)
            };
        }

        #endregion
    }
}

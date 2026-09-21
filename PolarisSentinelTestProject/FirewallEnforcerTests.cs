using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;
using PolarisSentinel.FirewallEnforement;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class FirewallEnforcerUnitTest
    {
        #region Block Tests

        [TestMethod]
        public void FirewallEnforcer_Block_ShouldCreateRule()
        {
            var (enforcer, _) = CreateEnforcer();

            var rule = enforcer.Block("203.0.113.10", 44321, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));

            Assert.IsTrue(enforcer.IsDryRun);
            Assert.AreEqual("R-1", rule.Id);
            Assert.AreEqual("PolarisSentinel_Block_A-RF-1", rule.Name);
            Assert.HasCount(1, enforcer.GetAllRules());
        }

        [TestMethod]
        public void FirewallEnforcer_Block_ShouldPersistFiveTuple()
        {
            var (enforcer, _) = CreateEnforcer();

            enforcer.Block("203.0.113.10", 44321, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));

            var stored = enforcer.GetAllRules()[0];
            Assert.AreEqual("203.0.113.10", stored.SourceIp);
            Assert.AreEqual(44321, stored.SourcePort);
            Assert.AreEqual("192.168.1.10", stored.DestinationIp);
            Assert.AreEqual(80, stored.DestinationPort);
            Assert.AreEqual(6, stored.Protocol);
        }

        // Blocking the same alert id again only pushes the expiry out.
        [TestMethod]
        public void FirewallEnforcer_SameAlertId_ShouldExtendExpiry()
        {
            var clock = new FakeTimeProvider();
            var (enforcer, _) = CreateEnforcer(clock);

            var first = enforcer.Block("203.0.113.10", 44321, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));
            var firstExpiry = first.ExpiresAt;

            clock.Advance(TimeSpan.FromMinutes(10));

            var second = enforcer.Block("203.0.113.10", 44321, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));

            Assert.HasCount(1, enforcer.GetAllRules());
            Assert.IsTrue(second.ExpiresAt > firstExpiry);
        }

        // A shorter duration never shortens an existing rule's expiry.
        [TestMethod]
        public void FirewallEnforcer_SameAlertIdShorterDuration_ShouldKeepExpiry()
        {
            var clock = new FakeTimeProvider();
            var (enforcer, _) = CreateEnforcer(clock);

            var first = enforcer.Block("203.0.113.10", 44321, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));
            var firstExpiry = first.ExpiresAt;

            var second = enforcer.Block("203.0.113.10", 44321, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(10));

            Assert.HasCount(1, enforcer.GetAllRules());
            Assert.AreEqual(firstExpiry, second.ExpiresAt);
        }

        [TestMethod]
        public void FirewallEnforcer_ZeroDuration_ShouldNotCreateRule()
        {
            var (enforcer, _) = CreateEnforcer();

            enforcer.Block("203.0.113.10", 44321, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.Zero);

            Assert.IsEmpty(enforcer.GetAllRules());
        }

        [TestMethod]
        public void FirewallEnforcer_Block_ShouldIncrementRuleIds()
        {
            var (enforcer, _) = CreateEnforcer();

            var first = enforcer.Block("203.0.113.10", 1, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));
            var second = enforcer.Block("198.51.100.23", 2, "192.168.1.10", 22, 6,
                PolicyAction.Block, "A-RF-2", AttackTypes.PortScan, TimeSpan.FromMinutes(60));

            Assert.AreEqual("R-1", first.Id);
            Assert.AreEqual("R-2", second.Id);
        }

        // A scope that constrains nothing becomes a single shared all-traffic rule.
        [TestMethod]
        public void FirewallEnforcer_BlockAnyScope_ShouldCreateSingleSharedRule()
        {
            var (enforcer, _) = CreateEnforcer();

            var first = enforcer.Block("203.0.113.10", 1, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60),
                FirewallRuleScope.Any);
            var second = enforcer.Block("198.51.100.23", 2, "192.168.1.20", 22, 6,
                PolicyAction.Block, "A-RF-2", AttackTypes.PortScan, TimeSpan.FromMinutes(60),
                FirewallRuleScope.Any);

            Assert.HasCount(1, enforcer.GetAllRules());
            Assert.AreEqual("PolarisSentinel_Block_ANY", first.Name);
            Assert.AreEqual(first.Id, second.Id);
            Assert.AreEqual(string.Empty, first.SourceIp);
            Assert.AreEqual(0, first.Protocol);
        }

        // Partial scopes keep only the fields the policy chose to block.
        [TestMethod]
        public void FirewallEnforcer_BlockPartialScope_ShouldKeepBlockedFieldsOnly()
        {
            var (enforcer, _) = CreateEnforcer();

            var rule = enforcer.Block("203.0.113.10", 44321, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60),
                new FirewallRuleScope { SourceIp = "203.0.113.10", Protocol = 6 });

            Assert.AreEqual("203.0.113.10", rule.SourceIp);
            Assert.AreEqual(0, rule.SourcePort);
            Assert.AreEqual(string.Empty, rule.DestinationIp);
            Assert.AreEqual(0, rule.DestinationPort);
            Assert.AreEqual(6, rule.Protocol);
            Assert.IsFalse(rule.Name.EndsWith("ANY", StringComparison.Ordinal));
        }

        #endregion

        #region Update / Remove Tests

        [TestMethod]
        public void FirewallEnforcer_Update_ShouldChangeFiveTuple()
        {
            var (enforcer, _) = CreateEnforcer();
            var rule = enforcer.Block("203.0.113.10", 1, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));

            var updated = enforcer.Update(rule.Id, "198.51.100.23", 2, "192.168.1.20", 443, 17,
                PolicyAction.Block, true, TimeSpan.FromMinutes(30));

            Assert.IsNotNull(updated);
            Assert.AreEqual("198.51.100.23", updated.SourceIp);
            Assert.AreEqual(443, updated.DestinationPort);
            Assert.AreEqual(17, updated.Protocol);
        }

        [TestMethod]
        public void FirewallEnforcer_UpdateUnknownId_ShouldReturnNull()
        {
            var (enforcer, _) = CreateEnforcer();
            var updated = enforcer.Update("R-99", "1.1.1.1", 1, "2.2.2.2", 2, 6,
                PolicyAction.Block, true, TimeSpan.FromMinutes(30));
            Assert.IsNull(updated);
        }

        [TestMethod]
        public void FirewallEnforcer_Remove_ShouldDeleteRule()
        {
            var (enforcer, _) = CreateEnforcer();
            var rule = enforcer.Block("203.0.113.10", 1, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));

            Assert.IsTrue(enforcer.Remove(rule.Id));
            Assert.IsEmpty(enforcer.GetAllRules());
        }

        [TestMethod]
        public void FirewallEnforcer_RemoveUnknownId_ShouldReturnFalse()
        {
            var (enforcer, _) = CreateEnforcer();
            Assert.IsFalse(enforcer.Remove("R-99"));
        }

        [TestMethod]
        public void FirewallEnforcer_RemoveAll_ShouldDeleteEveryRule()
        {
            var (enforcer, _) = CreateEnforcer();
            enforcer.Block("203.0.113.10", 1, "192.168.1.10", 80, 6, PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));
            enforcer.Block("198.51.100.23", 2, "192.168.1.10", 22, 6, PolicyAction.Block, "A-RF-2", AttackTypes.PortScan, TimeSpan.FromMinutes(60));

            Assert.AreEqual(2, enforcer.RemoveAll());
            Assert.IsEmpty(enforcer.GetAllRules());
        }

        #endregion

        #region Expiry Tests

        [TestMethod]
        public void FirewallEnforcer_RemoveExpired_ShouldKeepActiveRule()
        {
            var clock = new FakeTimeProvider();
            var (enforcer, _) = CreateEnforcer(clock);
            enforcer.Block("203.0.113.10", 1, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));

            clock.Advance(TimeSpan.FromMinutes(30));
            Assert.AreEqual(0, enforcer.RemoveExpired());
            Assert.HasCount(1, enforcer.GetAllRules());
        }

        [TestMethod]
        public void FirewallEnforcer_RemoveExpired_ShouldDeleteExpiredRule()
        {
            var clock = new FakeTimeProvider();
            var (enforcer, _) = CreateEnforcer(clock);
            enforcer.Block("203.0.113.10", 1, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));

            clock.Advance(TimeSpan.FromMinutes(61));
            Assert.AreEqual(1, enforcer.RemoveExpired());
            Assert.IsEmpty(enforcer.GetAllRules());
        }

        #endregion

        #region Lookup Tests

        [TestMethod]
        public void FirewallEnforcer_GetById_ShouldReturnRule()
        {
            var (enforcer, _) = CreateEnforcer();
            var rule = enforcer.Block("203.0.113.10", 1, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));

            Assert.IsNotNull(enforcer.GetById(rule.Id));
            Assert.IsNull(enforcer.GetById("R-99"));
        }

        #endregion

        #region Helper Methods

        // DryRun keeps the tests in memory; the repository is still written.
        private static (WindowsFirewallEnforcer Enforcer, FakeRuleRepository Repository) CreateEnforcer(
            FakeTimeProvider? clock = null)
        {
            var repository = new FakeRuleRepository();
            var enforcer = new WindowsFirewallEnforcer(
                repository,
                Options.Create(new FirewallOptions()),
                clock ?? new FakeTimeProvider(),
                NullLogger<WindowsFirewallEnforcer>.Instance);
            return (enforcer, repository);
        }

        #endregion
    }
}

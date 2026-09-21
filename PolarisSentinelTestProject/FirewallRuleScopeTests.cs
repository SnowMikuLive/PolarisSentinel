using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class FirewallRuleScopeUnitTest
    {
        // Every field set to Block keeps the exact 5-tuple.
        [TestMethod]
        public void FromPolicy_AllBlock_ShouldKeepFiveTuple()
        {
            var policy = new Policy
            {
                RuleSourceIpAction = PolicyAction.Block,
                RuleSourcePortAction = PolicyAction.Block,
                RuleDestinationIpAction = PolicyAction.Block,
                RuleDestinationPortAction = PolicyAction.Block
            };

            var scope = FirewallRuleScope.FromPolicy(policy, "203.0.113.10", 44321, "192.168.1.10", 80, 6);

            Assert.AreEqual("203.0.113.10", scope.SourceIp);
            Assert.AreEqual(44321, scope.SourcePort);
            Assert.AreEqual("192.168.1.10", scope.DestinationIp);
            Assert.AreEqual(80, scope.DestinationPort);
            Assert.AreEqual(6, scope.Protocol);
            Assert.IsFalse(scope.IsAny);
        }

        // Any on every field means the rule blocks all traffic.
        [TestMethod]
        public void FromPolicy_AllAllow_ShouldBeAnyScope()
        {
            var policy = new Policy
            {
                RuleSourceIpAction = PolicyAction.Allow,
                RuleSourcePortAction = PolicyAction.Allow,
                RuleDestinationIpAction = PolicyAction.Allow,
                RuleDestinationPortAction = PolicyAction.Allow
            };

            // Protocol 0 keeps the rule protocol-agnostic; a specific protocol is still a constraint.
            var scope = FirewallRuleScope.FromPolicy(policy, "203.0.113.10", 44321, "192.168.1.10", 80, 0);

            Assert.IsTrue(scope.IsAny);
            Assert.AreEqual(string.Empty, scope.SourceIp);
            Assert.AreEqual(0, scope.SourcePort);
            Assert.AreEqual(string.Empty, scope.DestinationIp);
            Assert.AreEqual(0, scope.DestinationPort);
        }

        // Mixed actions produce a partially constrained scope.
        [TestMethod]
        public void FromPolicy_MixedActions_ShouldConstrainBlockedFieldsOnly()
        {
            var policy = new Policy
            {
                RuleSourceIpAction = PolicyAction.Block,
                RuleSourcePortAction = PolicyAction.Allow,
                RuleDestinationIpAction = PolicyAction.Allow,
                RuleDestinationPortAction = PolicyAction.Block
            };

            var scope = FirewallRuleScope.FromPolicy(policy, "203.0.113.10", 44321, "192.168.1.10", 80, 6);

            Assert.AreEqual("203.0.113.10", scope.SourceIp);
            Assert.AreEqual(0, scope.SourcePort);
            Assert.AreEqual(string.Empty, scope.DestinationIp);
            Assert.AreEqual(80, scope.DestinationPort);
            Assert.IsFalse(scope.IsAny);
        }

        // ApplyTo writes the scope onto an existing rule.
        [TestMethod]
        public void ApplyTo_ShouldOverwriteRuleFields()
        {
            var rule = new Rule
            {
                SourceIp = "1.1.1.1",
                SourcePort = 1,
                DestinationIp = "2.2.2.2",
                DestinationPort = 2,
                Protocol = 17
            };

            FirewallRuleScope.Any.ApplyTo(rule);

            Assert.AreEqual(string.Empty, rule.SourceIp);
            Assert.AreEqual(0, rule.SourcePort);
            Assert.AreEqual(string.Empty, rule.DestinationIp);
            Assert.AreEqual(0, rule.DestinationPort);
            Assert.AreEqual((byte)0, rule.Protocol);
        }
    }
}

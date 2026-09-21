using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.FirewallEnforement;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class ManualRuleCreationUnitTest
    {
        // The Rules page creates a rule without a policy scope, so the exact
        // 5-tuple (including the protocol) must be stored.
        [TestMethod]
        public void ManualRule_Block_ShouldStoreSelectedProtocol()
        {
            var (enforcer, _) = CreateEnforcer();

            var rule = enforcer.Block("203.0.113.10", 44321, "192.168.1.10", 80, 6,
                PolicyAction.Block, null, null, TimeSpan.FromMinutes(60));

            Assert.AreEqual((byte)6, rule.Protocol);
            Assert.AreEqual(44321, rule.SourcePort);
            Assert.AreEqual(80, rule.DestinationPort);
        }

        // Protocol "Any" (0) must round-trip as 0, not as a wildcard scope.
        [TestMethod]
        public void ManualRule_Block_AnyProtocol_ShouldStayAny()
        {
            var (enforcer, _) = CreateEnforcer();

            var rule = enforcer.Block("203.0.113.10", 44321, "192.168.1.10", 80, 0,
                PolicyAction.Block, null, null, TimeSpan.FromMinutes(60));

            Assert.AreEqual((byte)0, rule.Protocol);
            Assert.AreEqual("203.0.113.10", rule.SourceIp);
        }

        // AlertId is a foreign key into Alerts, so a manual rule must leave it null.
        [TestMethod]
        public void ManualRule_Block_ShouldHaveNoAlertId()
        {
            var (enforcer, _) = CreateEnforcer();

            var rule = enforcer.Block("203.0.113.10", 1, "192.168.1.10", 80, 6,
                PolicyAction.Block, null, null, TimeSpan.FromMinutes(60));

            Assert.IsNull(rule.AlertId);
            // The name falls back to the generated rule id.
            Assert.AreEqual("PolarisSentinel_Block_R-1", rule.Name);
        }

        // A detector rule still keeps its alert id in the name.
        [TestMethod]
        public void DetectorRule_Block_ShouldKeepAlertIdInName()
        {
            var (enforcer, _) = CreateEnforcer();

            var rule = enforcer.Block("203.0.113.10", 1, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));

            Assert.AreEqual("PolarisSentinel_Block_A-RF-1", rule.Name);
            Assert.AreEqual("A-RF-1", rule.AlertId);
        }

        private static (WindowsFirewallEnforcer Enforcer, FakeRuleRepository Repository) CreateEnforcer()
        {
            var repository = new FakeRuleRepository();
            var enforcer = new WindowsFirewallEnforcer(
                repository,
                Options.Create(new FirewallOptions()),
                new FakeTimeProvider(),
                NullLogger<WindowsFirewallEnforcer>.Instance);
            return (enforcer, repository);
        }
    }
}

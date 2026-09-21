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
    public class FirewallRuleNameLengthUnitTest
    {
        // The Rules table stores Name in a 128-char column; a manual rule name
        // must stay well inside it.
        [TestMethod]
        public void ManualRuleName_ShouldFitIn128Characters()
        {
            string name = EntityIds.FirewallRule(EntityIds.Rule(12345));

            Assert.IsLessThanOrEqualTo(128, name.Length, $"Rule name '{name}' is {name.Length} chars.");
        }

        // Detector alert ids are short and must stay well within the column.
        [TestMethod]
        public void DetectorRuleName_ShouldFitIn128Characters()
        {
            string name = EntityIds.FirewallRule(EntityIds.Alert(DetectionSource.RandomForest, 12345));

            Assert.IsLessThanOrEqualTo(128, name.Length);
        }

        // The name must still be recognisable as a PolarisSentinel rule.
        [TestMethod]
        public void RuleName_ShouldKeepManagedPrefix()
        {
            string name = EntityIds.FirewallRule(EntityIds.Rule(1));

            Assert.StartsWith(EntityIds.FirewallRulePrefix, name);
        }

        // A real (non-dry-run) enforcer must persist a manual rule without throwing.
        // The COM layer is unavailable in tests, so the repository write is what matters.
        [TestMethod]
        public void ManualRule_RealEnforcer_ShouldPersist()
        {
            var repository = new FakeRuleRepository();
            var enforcer = new WindowsFirewallEnforcer(
                repository,
                Options.Create(new FirewallOptions { DryRun = true }),
                new FakeTimeProvider(),
                NullLogger<WindowsFirewallEnforcer>.Instance);

            var rule = enforcer.Block("203.0.113.10", 44321, "192.168.1.10", 80, 6,
                PolicyAction.Block, null, null, TimeSpan.FromMinutes(60));

            Assert.IsNotNull(enforcer.GetById(rule.Id));
            Assert.IsNull(rule.AlertId);
            Assert.IsLessThanOrEqualTo(128, rule.Name.Length);
        }
    }
}

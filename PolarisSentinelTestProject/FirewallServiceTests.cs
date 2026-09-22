using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Extensions.DependencyInjection;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.FirewallEnforement;
using PolarisSentinel.Web.Service;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class FirewallServiceUnitTest
    {
        // The rules page reads every rule the application created.
        [TestMethod]
        public void FirewallRulesPage_GetAllRules_ShouldReturnCreatedRule()
        {
            var repository = new FakeRuleRepository();
            var clock = new FakeTimeProvider();
            var enforcer = new WindowsFirewallEnforcer(repository, Options.Create(new FirewallOptions()),
                clock, NullLogger<WindowsFirewallEnforcer>.Instance);

            enforcer.Block("203.0.113.10", 44321, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", "P-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));

            var rules = enforcer.GetAllRules();
            Assert.HasCount(1, rules);
            Assert.AreEqual("203.0.113.10", rules[0].SourceIp);
        }

        [TestMethod]
        public void FirewallRulesPage_RemoveAll_ShouldRemoveCreatedRules()
        {
            var repository = new FakeRuleRepository();
            var clock = new FakeTimeProvider();
            var enforcer = new WindowsFirewallEnforcer(repository, Options.Create(new FirewallOptions()),
                clock, NullLogger<WindowsFirewallEnforcer>.Instance);

            enforcer.Block("203.0.113.10", 1, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", "P-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));

            Assert.AreEqual(1, enforcer.RemoveAll());
            Assert.IsEmpty(enforcer.GetAllRules());
        }

        // The sweeper removes rules whose expiry has passed.
        [TestMethod]
        public void FirewallRuleSweeper_Start_ShouldRemoveExpiredRule()
        {
            var repository = new FakeRuleRepository();
            var clock = new FakeTimeProvider();
            var enforcer = new WindowsFirewallEnforcer(repository, Options.Create(new FirewallOptions()),
                clock, NullLogger<WindowsFirewallEnforcer>.Instance);

            enforcer.Block("203.0.113.10", 1, "192.168.1.10", 80, 6,
                PolicyAction.Block, "A-RF-1", "P-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));
            clock.Advance(TimeSpan.FromMinutes(61));

            using var serviceProvider = new ServiceCollection()
                .AddScoped<IFirewallEnforcer>(_ => enforcer)
                .BuildServiceProvider();
            var sweeper = new FirewallRuleSweeper(
                serviceProvider.GetRequiredService<IServiceScopeFactory>(),
                Options.Create(new FirewallOptions()),
                clock);
            sweeper.StartAsync(CancellationToken.None).GetAwaiter().GetResult();

            Assert.IsEmpty(enforcer.GetAllRules());
            sweeper.StopAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
    }
}

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;
using PolarisSentinel.FirewallEnforement;

namespace PolarisSentienlUnitTestProject;

// Core enforcement behaviour: building the rule for an action and removing rules.
[TestClass]
public class FirewallEnforcerUnitTest
{
    // Each action maps to the right rule: 5-tuple mirrors the alert, block target follows the action.
    [TestMethod]
    public void Apply_ShouldBuildRuleForEachAction()
    {
        var (enforcer, _) = CreateEnforcer();
        var alert = CreateAlert();

        var inboundIp = enforcer.Apply(Decision(alert, PolicyAction.BlockInboundIp), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));
        Assert.AreEqual("203.0.113.10", inboundIp.SourceIp);
        Assert.AreEqual("192.168.1.10", inboundIp.DestinationIp);
        Assert.IsTrue(inboundIp.BlocksAddress);
        Assert.AreEqual("203.0.113.10", inboundIp.BlockedIp);

        var inboundPort = enforcer.Apply(Decision(CreateAlert("A-RF-2"), PolicyAction.BlockInboundPort), "P-1", "A-RF-2", AttackTypes.DoS, TimeSpan.FromMinutes(60));
        Assert.IsFalse(inboundPort.BlocksAddress);
        Assert.AreEqual(80, inboundPort.BlockedPort);

        var outboundIp = enforcer.Apply(Decision(CreateAlert("A-RF-3"), PolicyAction.BlockOutboundIp), "P-1", "A-RF-3", AttackTypes.DoS, TimeSpan.FromMinutes(60));
        Assert.AreEqual("192.168.1.10", outboundIp.BlockedIp);
    }

    [TestMethod]
    public void RemoveAndRemoveAll_ShouldDeleteRules()
    {
        var (enforcer, _) = CreateEnforcer();
        var alert = CreateAlert();
        var rule = enforcer.Apply(Decision(alert, PolicyAction.BlockInboundIp), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));

        Assert.IsTrue(enforcer.Remove(rule.Id));
        Assert.IsEmpty(enforcer.GetAllRules());

        var first = CreateAlert("A-RF-1");
        first.SourceIp = "203.0.113.1";
        var second = CreateAlert("A-RF-2");
        second.SourceIp = "203.0.113.2";
        enforcer.Apply(Decision(first, PolicyAction.BlockInboundIp), "P-1", "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));
        enforcer.Apply(Decision(second, PolicyAction.BlockInboundIp), "P-1", "A-RF-2", AttackTypes.PortScan, TimeSpan.FromMinutes(60));

        Assert.AreEqual(2, enforcer.RemoveAll());
        Assert.IsEmpty(enforcer.GetAllRules());
    }

    #region Helper Methods

    private static (TestFirewallEnforcer Enforcer, FakeRuleRepository Repository) CreateEnforcer()
    {
        var repository = new FakeRuleRepository();
        var enforcer = new TestFirewallEnforcer(repository, new FakeTimeProvider());
        return (enforcer, repository);
    }

    // Keeps the test off the real Windows Firewall COM API when a rule is removed.
    private sealed class TestFirewallEnforcer : WindowsFirewallEnforcer
    {
        public TestFirewallEnforcer(FakeRuleRepository repository, FakeTimeProvider clock)
            : base(repository, Options.Create(new FirewallOptions { DryRun = true }),
                new FirewallRuntimeState(dryRun: true), clock, NullLogger<WindowsFirewallEnforcer>.Instance)
        {
        }

        protected override void RemoveWindowsRule(string ruleName)
        {
        }
    }

    private static PolicyDecision Decision(Alert alert, PolicyAction action) =>
        new() { Alert = alert, Action = action, PolicyId = "P-1", BlockDurationMinutes = 60 };

    private static Alert CreateAlert(string id = "A-RF-1") => new()
    {
        Id = id,
        DetectionSource = DetectionSource.RandomForest,
        AttackType = AttackTypes.DoS,
        ConfidenceScore = 0.95f,
        SourceIp = "203.0.113.10",
        SourcePort = 44321,
        DestinationIp = "192.168.1.10",
        DestinationPort = 80,
        Protocol = ProtocolNumbers.Tcp
    };

    #endregion
}

using Microsoft.Extensions.Logging.Abstractions;
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
    [TestMethod]
    public void Apply_ShouldBuildRuleForEachAction()
    {
        var (enforcer, _, _) = CreateEnforcer();
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

        var outboundPort = enforcer.Apply(Decision(CreateAlert("A-RF-4"), PolicyAction.BlockOutboundPort), "P-1", "A-RF-4", AttackTypes.DoS, TimeSpan.FromMinutes(60));
        Assert.IsFalse(outboundPort.BlocksAddress);
        Assert.AreEqual(80, outboundPort.BlockedPort);
    }

    [TestMethod]
    public void AddressBlock_ShouldBeProtocolAgnostic()
    {
        var alert = CreateAlert();

        var inbound = FirewallRuleSpec.TryCreate(PolicyAction.BlockInboundIp, alert, out var error);
        Assert.IsNull(error);
        Assert.IsNotNull(inbound);
        Assert.AreEqual("203.0.113.10", inbound!.RemoteAddress);
        Assert.AreEqual(0, inbound.Protocol, "An inbound IP block must not inherit the alert protocol.");
        Assert.IsNull(inbound.LocalPort);
        Assert.IsNull(inbound.RemotePort);

        var outbound = FirewallRuleSpec.TryCreate(PolicyAction.BlockOutboundIp, alert, out _);
        Assert.AreEqual("192.168.1.10", outbound!.RemoteAddress);
        Assert.AreEqual(0, outbound.Protocol, "An outbound IP block must not inherit the alert protocol.");
    }

    [TestMethod]
    public void Reconcile_ShouldRemoveUntrackedRules()
    {
        var (enforcer, repository, gateway) = CreateEnforcer();
        enforcer.Apply(Decision(CreateAlert(), PolicyAction.BlockInboundIp), "P-1", "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));

        var tracked = repository.GetAllAsync().GetAwaiter().GetResult().Single().Name;
        gateway.ManagedNames =
        [
            tracked,
            "PolarisSentinel_Block_A-34",
            "PolarisSentinel_Block_A-35"
        ];

        int changes = enforcer.Reconcile();

        Assert.AreEqual(2, changes);
        CollectionAssert.AreEquivalent(
            new[] { "PolarisSentinel_Block_A-34", "PolarisSentinel_Block_A-35" },
            gateway.Removed);
    }

    #region Helper Methods

    private static (WindowsFirewallEnforcer Enforcer, FakeRuleRepository Repository, FakeFirewallGateway Gateway) CreateEnforcer()
    {
        var repository = new FakeRuleRepository();
        var gateway = new FakeFirewallGateway();
        var enforcer = new WindowsFirewallEnforcer(
            repository, gateway, new FirewallRuntimeState(dryRun: true), new FakeTimeProvider(),
            NullLogger<WindowsFirewallEnforcer>.Instance);
        return (enforcer, repository, gateway);
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

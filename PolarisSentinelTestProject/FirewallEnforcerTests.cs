using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Application;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;
using PolarisSentinel.FirewallEnforement;

namespace PolarisSentienlUnitTestProject
{
    // Key firewall-enforcer behaviour: rule construction per action, validation, and lifecycle.
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

        // ICMP has no ports and Any cannot carry a port filter: both must be rejected.
        [TestMethod]
        public void Apply_PortActionOnIcmpOrAnyProtocol_ShouldThrow()
        {
            var (enforcer, _) = CreateEnforcer();

            Assert.ThrowsExactly<InvalidOperationException>(() =>
                enforcer.Apply(Decision(CreateAlert(protocol: ProtocolNumbers.Icmp), PolicyAction.BlockInboundPort), "P-1", "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60)));

            Assert.ThrowsExactly<InvalidOperationException>(() =>
                enforcer.Apply(Decision(CreateAlert(protocol: 0), PolicyAction.BlockInboundPort), "P-1", "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60)));
        }

        // CIDR prefixes are valid and preserved.
        [TestMethod]
        [DataRow("203.0.113.0/24")]
        [DataRow("2001:db8::/64")]
        public void Apply_BlockInboundIpWithCidr_ShouldKeepSourceAddress(string address)
        {
            var (enforcer, _) = CreateEnforcer();
            var alert = CreateAlert();
            alert.SourceIp = address;

            var rule = enforcer.Apply(Decision(alert, PolicyAction.BlockInboundIp), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));

            Assert.AreEqual(address, rule.SourceIp);
        }

        [TestMethod]
        [DataRow("203.0.113.0/24", true)]
        [DataRow("203.0.113.0/33", false)]
        [DataRow("203.0.113.0/abc", false)]
        public void Validate_Cidr_ShouldCheckPrefix(string address, bool valid)
        {
            var (enforcer, _) = CreateEnforcer();
            var service = new RuleManagementService(enforcer, new FakeUnitOfWork());
            var rule = new Rule { SourceIp = address, Action = PolicyAction.BlockInboundIp };

            var errors = service.Validate(rule);

            Assert.AreEqual(valid, !errors.ContainsKey(nameof(Rule.SourceIp)));
        }

        [TestMethod]
        public void Update_ShouldChangeFiveTupleAndStatus()
        {
            var (enforcer, _) = CreateEnforcer();
            var alert = CreateAlert();
            var rule = enforcer.Apply(Decision(alert, PolicyAction.BlockInboundIp), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));

            var updated = enforcer.Update(rule.Id, "198.51.100.23", 2, "192.168.1.20", 443, ProtocolNumbers.Udp,
                PolicyAction.BlockOutboundPort, RuleStatus.Inactive, TimeSpan.FromMinutes(30));

            Assert.IsNotNull(updated);
            Assert.AreEqual("198.51.100.23", updated.SourceIp);
            Assert.AreEqual(443, updated.DestinationPort);
            Assert.AreEqual(RuleStatus.Inactive, updated.Status);
            Assert.IsNull(enforcer.Update("R-99", "1.1.1.1", 1, "2.2.2.2", 2, ProtocolNumbers.Tcp,
                PolicyAction.BlockInboundIp, RuleStatus.Active, TimeSpan.FromMinutes(30)));
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

        // Repeated attacks on the same target reuse and extend one rule instead of piling up.
        [TestMethod]
        public void Apply_SameTarget_ShouldReuseAndExtendOneRule()
        {
            var clock = new FakeTimeProvider();
            var (enforcer, _) = CreateEnforcer(clock);
            var first = enforcer.Apply(Decision(CreateAlert("A-RF-1"), PolicyAction.BlockInboundIp), "P-1", "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));
            var firstExpiry = first.ExpiresAt;

            clock.Advance(TimeSpan.FromMinutes(10));
            var second = enforcer.Apply(Decision(CreateAlert("A-RF-2"), PolicyAction.BlockInboundIp), "P-1", "A-RF-2", AttackTypes.DoS, TimeSpan.FromMinutes(60));

            Assert.HasCount(1, enforcer.GetAllRules());
            Assert.AreEqual(first.Id, second.Id);
            Assert.IsTrue(second.ExpiresAt > firstExpiry);
        }

        [TestMethod]
        public void RemoveExpired_ShouldMarkRuleExpired()
        {
            var clock = new FakeTimeProvider();
            var (enforcer, _) = CreateEnforcer(clock);
            var alert = CreateAlert();
            enforcer.Apply(Decision(alert, PolicyAction.BlockInboundIp), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));

            clock.Advance(TimeSpan.FromMinutes(30));
            Assert.AreEqual(0, enforcer.RemoveExpired());

            clock.Advance(TimeSpan.FromMinutes(31));
            Assert.AreEqual(1, enforcer.RemoveExpired());
            Assert.AreEqual(RuleStatus.Expired, enforcer.GetAllRules().Single().Status);
        }

        // Dry-run still removes rules left on the system from earlier real enforcement.
        [TestMethod]
        public void DryRun_ShouldStillRemoveExistingWindowsRule()
        {
            var (enforcer, _) = CreateEnforcer();
            var alert = CreateAlert();
            var rule = enforcer.Apply(Decision(alert, PolicyAction.BlockInboundIp), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));
            enforcer.WindowsRules.Add(rule.Name);
            enforcer.SetDryRun(true);

            Assert.IsTrue(enforcer.Remove(rule.Id));
            Assert.IsEmpty(enforcer.WindowsRules);
            Assert.IsTrue(enforcer.IsDryRun);
        }

        #region Helper Methods

        private static (TestFirewallEnforcer Enforcer, FakeRuleRepository Repository) CreateEnforcer(
            FakeTimeProvider? clock = null)
        {
            var repository = new FakeRuleRepository();
            var enforcer = new TestFirewallEnforcer(repository, clock ?? new FakeTimeProvider());
            return (enforcer, repository);
        }

        private sealed class TestFirewallEnforcer : WindowsFirewallEnforcer
        {
            public HashSet<string> WindowsRules { get; } = new();

            public TestFirewallEnforcer(FakeRuleRepository repository, FakeTimeProvider clock)
                : base(repository, Options.Create(new FirewallOptions { DryRun = true }),
                    new FirewallRuntimeState(dryRun: true), clock, NullLogger<WindowsFirewallEnforcer>.Instance)
            {
            }

            protected override void RemoveWindowsRule(string ruleName) => WindowsRules.Remove(ruleName);
        }

        private static PolicyDecision Decision(Alert alert, PolicyAction action) =>
            new() { Alert = alert, Action = action, PolicyId = "P-1", BlockDurationMinutes = 60 };

        private static Alert CreateAlert(string id = "A-RF-1", byte protocol = ProtocolNumbers.Tcp) => new()
        {
            Id = id,
            DetectionSource = DetectionSource.RandomForest,
            AttackType = AttackTypes.DoS,
            ConfidenceScore = 0.95f,
            SourceIp = "203.0.113.10",
            SourcePort = 44321,
            DestinationIp = "192.168.1.10",
            DestinationPort = 80,
            Protocol = protocol
        };

        #endregion
    }
}

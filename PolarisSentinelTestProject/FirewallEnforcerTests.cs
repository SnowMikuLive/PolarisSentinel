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
    [TestClass]
    public class FirewallEnforcerUnitTest
    {
        [TestMethod]
        public void Apply_BlockInboundIp_ShouldConstrainRemoteAddress()
        {
            var (enforcer, _) = CreateEnforcer();
            var alert = CreateAlert();

            var rule = enforcer.Apply(Decision(alert, PolicyAction.BlockInboundIp), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));

            Assert.IsTrue(enforcer.IsDryRun);
            Assert.AreEqual("PolarisSentinel_Block_A-RF-1", rule.Name);
            Assert.AreEqual("203.0.113.10", rule.SourceIp);
            Assert.AreEqual(string.Empty, rule.DestinationIp);
            Assert.IsNull(rule.SourcePort);
            Assert.AreEqual((byte)ProtocolNumbers.Tcp, rule.Protocol);
            Assert.AreEqual("P-1", rule.PolicyId);
            Assert.AreEqual("A-RF-1", rule.AlertId);
        }

        [TestMethod]
        public void Apply_BlockInboundPort_ShouldConstrainLocalPort()
        {
            var (enforcer, _) = CreateEnforcer();
            var alert = CreateAlert();

            var rule = enforcer.Apply(Decision(alert, PolicyAction.BlockInboundPort), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));

            Assert.AreEqual(80, rule.DestinationPort);
            Assert.IsNull(rule.SourcePort);
        }

        [TestMethod]
        public void Apply_BlockOutboundIp_ShouldConstrainDestinationAddress()
        {
            var (enforcer, _) = CreateEnforcer();
            var alert = CreateAlert();

            var rule = enforcer.Apply(Decision(alert, PolicyAction.BlockOutboundIp), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));

            Assert.AreEqual("192.168.1.10", rule.DestinationIp);
            Assert.AreEqual(string.Empty, rule.SourceIp);
            Assert.AreEqual(PolicyAction.BlockOutboundIp, rule.Action);
        }

        // ICMP has no ports, so a port action must be rejected with a clear error.
        [TestMethod]
        public void Apply_PortActionOnIcmp_ShouldThrow()
        {
            var (enforcer, _) = CreateEnforcer();
            var alert = CreateAlert(protocol: ProtocolNumbers.Icmp);

            Assert.ThrowsExactly<InvalidOperationException>(() =>
                enforcer.Apply(Decision(alert, PolicyAction.BlockInboundPort), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60)));
        }

        // The Any protocol cannot carry a port filter, so a port action must be rejected
        // instead of silently widening into an all-port block.
        [TestMethod]
        public void Apply_PortActionOnAnyProtocol_ShouldThrow()
        {
            var (enforcer, _) = CreateEnforcer();
            var alert = CreateAlert(protocol: 0);

            Assert.ThrowsExactly<InvalidOperationException>(() =>
                enforcer.Apply(Decision(alert, PolicyAction.BlockInboundPort), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60)));
        }

        // A CIDR source is a valid inbound scope; the prefix must be preserved.
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
        [DataRow("2001:db8::/64", true)]
        [DataRow("203.0.113.0/33", false)]
        [DataRow("2001:db8::/129", false)]
        [DataRow("203.0.113.0/abc", false)]
        public void Validate_Cidr_ShouldCheckPrefix(string address, bool valid)
        {
            var (enforcer, _) = CreateEnforcer();
            var service = new RuleManagementService(enforcer, new FakeUnitOfWork());
            var rule = new Rule { SourceIp = address, Action = PolicyAction.BlockInboundIp };

            var errors = service.Validate(rule);

            Assert.AreEqual(valid, !errors.ContainsKey(nameof(Rule.SourceIp)));
        }

        // A null alert id marks a manual rule with no originating alert.
        [TestMethod]
        public void Apply_ManualRule_ShouldHaveNullAssociations()
        {
            var (enforcer, _) = CreateEnforcer();
            var alert = CreateAlert();

            var rule = enforcer.Apply(Decision(alert, PolicyAction.BlockInboundIp), null, null, null, TimeSpan.FromMinutes(60));

            Assert.IsNull(rule.PolicyId);
            Assert.IsNull(rule.AlertId);
            Assert.IsTrue(rule.Name.StartsWith(EntityIds.FirewallRulePrefix, StringComparison.Ordinal));
        }

        [TestMethod]
        public void Apply_SameAlertId_ShouldExtendExpiryAndKeepOneRule()
        {
            var clock = new FakeTimeProvider();
            var (enforcer, _) = CreateEnforcer(clock);
            var alert = CreateAlert();

            var first = enforcer.Apply(Decision(alert, PolicyAction.BlockInboundIp), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));
            var firstExpiry = first.ExpiresAt;

            clock.Advance(TimeSpan.FromMinutes(10));
            var second = enforcer.Apply(Decision(alert, PolicyAction.BlockInboundIp), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));

            Assert.HasCount(1, enforcer.GetAllRules());
            Assert.IsTrue(second.ExpiresAt > firstExpiry);
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
        }

        [TestMethod]
        public void Update_UnknownId_ShouldReturnNull()
        {
            var (enforcer, _) = CreateEnforcer();
            Assert.IsNull(enforcer.Update("R-99", "1.1.1.1", 1, "2.2.2.2", 2, ProtocolNumbers.Tcp,
                PolicyAction.BlockInboundIp, RuleStatus.Active, TimeSpan.FromMinutes(30)));
        }

        [TestMethod]
        public void Remove_ShouldDeleteRule()
        {
            var (enforcer, _) = CreateEnforcer();
            var alert = CreateAlert();
            var rule = enforcer.Apply(Decision(alert, PolicyAction.BlockInboundIp), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));

            Assert.IsTrue(enforcer.Remove(rule.Id));
            Assert.IsEmpty(enforcer.GetAllRules());
            Assert.IsFalse(enforcer.Remove("R-99"));
        }

        [TestMethod]
        public void RemoveAll_ShouldDeleteEveryRule()
        {
            var (enforcer, _) = CreateEnforcer();
            enforcer.Apply(Decision(CreateAlert("A-RF-1"), PolicyAction.BlockInboundIp), "P-1", "A-RF-1", AttackTypes.DoS, TimeSpan.FromMinutes(60));
            enforcer.Apply(Decision(CreateAlert("A-RF-2"), PolicyAction.BlockInboundIp), "P-1", "A-RF-2", AttackTypes.PortScan, TimeSpan.FromMinutes(60));

            Assert.AreEqual(2, enforcer.RemoveAll());
            Assert.IsEmpty(enforcer.GetAllRules());
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
            Assert.AreEqual(0, enforcer.RemoveExpired());
        }

        #region Helper Methods

        private static (WindowsFirewallEnforcer Enforcer, FakeRuleRepository Repository) CreateEnforcer(
            FakeTimeProvider? clock = null)
        {
            var repository = new FakeRuleRepository();
            var enforcer = new WindowsFirewallEnforcer(
                repository,
                Options.Create(new FirewallOptions { DryRun = true }),
                new FirewallRuntimeState(dryRun: true),
                clock ?? new FakeTimeProvider(),
                NullLogger<WindowsFirewallEnforcer>.Instance);
            return (enforcer, repository);
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

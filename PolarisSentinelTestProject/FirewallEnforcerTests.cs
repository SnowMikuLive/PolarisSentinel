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
            // The rule's 5-tuple mirrors the alert exactly.
            Assert.AreEqual("203.0.113.10", rule.SourceIp);
            Assert.AreEqual(44321, rule.SourcePort);
            Assert.AreEqual("192.168.1.10", rule.DestinationIp);
            Assert.AreEqual(80, rule.DestinationPort);
            // The inbound-IP action blocks the alert's source address.
            Assert.IsTrue(rule.BlocksAddress);
            Assert.AreEqual("203.0.113.10", rule.BlockedIp);
            Assert.IsNull(rule.BlockedPort);
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

            // The 5-tuple mirrors the alert; the action blocks the destination port.
            Assert.AreEqual(80, rule.DestinationPort);
            Assert.AreEqual(44321, rule.SourcePort);
            Assert.IsFalse(rule.BlocksAddress);
            Assert.AreEqual(80, rule.BlockedPort);
            Assert.IsNull(rule.BlockedIp);
        }

        [TestMethod]
        public void Apply_BlockOutboundIp_ShouldConstrainDestinationAddress()
        {
            var (enforcer, _) = CreateEnforcer();
            var alert = CreateAlert();

            var rule = enforcer.Apply(Decision(alert, PolicyAction.BlockOutboundIp), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));

            // The 5-tuple mirrors the alert; the outbound-IP action blocks the destination.
            Assert.AreEqual("203.0.113.10", rule.SourceIp);
            Assert.AreEqual("192.168.1.10", rule.DestinationIp);
            Assert.IsTrue(rule.BlocksAddress);
            Assert.AreEqual("192.168.1.10", rule.BlockedIp);
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

        [TestMethod]
        [DataRow("Remove")]
        [DataRow("RemoveAll")]
        [DataRow("Expire")]
        [DataRow("Deactivate")]
        public void DryRun_ShouldStillRemoveExistingWindowsRule(string operation)
        {
            var clock = new FakeTimeProvider();
            var (enforcer, _) = CreateEnforcer(clock);
            var alert = CreateAlert();
            var rule = enforcer.Apply(Decision(alert, PolicyAction.BlockInboundIp), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));
            // Simulate a Windows rule left from earlier real enforcement.
            enforcer.WindowsRules.Add(rule.Name);
            enforcer.SetDryRun(true);

            switch (operation)
            {
                case "Remove":
                    Assert.IsTrue(enforcer.Remove(rule.Id));
                    Assert.IsEmpty(enforcer.GetAllRules());
                    break;
                case "RemoveAll":
                    Assert.AreEqual(1, enforcer.RemoveAll());
                    Assert.IsEmpty(enforcer.GetAllRules());
                    break;
                case "Expire":
                    clock.Advance(TimeSpan.FromMinutes(61));
                    Assert.AreEqual(1, enforcer.RemoveExpired());
                    Assert.AreEqual(RuleStatus.Expired, enforcer.GetById(rule.Id)!.Status);
                    break;
                case "Deactivate":
                    var updated = enforcer.Update(rule.Id, rule.SourceIp ?? string.Empty, 0, rule.DestinationIp ?? string.Empty, 0,
                        ProtocolNumbers.Tcp, rule.Action, RuleStatus.Inactive, TimeSpan.FromMinutes(60));
                    Assert.AreEqual(RuleStatus.Inactive, updated!.Status);
                    break;
            }

            Assert.IsEmpty(enforcer.WindowsRules);
            Assert.IsTrue(enforcer.IsDryRun);
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void FailedCleanup_ShouldKeepRuleRecord(bool deactivate)
        {
            var (enforcer, _) = CreateEnforcer();
            var alert = CreateAlert();
            var rule = enforcer.Apply(Decision(alert, PolicyAction.BlockInboundIp), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));
            enforcer.WindowsRules.Add(rule.Name);
            enforcer.FailRemoval = true;

            Assert.ThrowsExactly<InvalidOperationException>(() =>
            {
                if (deactivate)
                    enforcer.Update(rule.Id, rule.SourceIp ?? string.Empty, 0, rule.DestinationIp ?? string.Empty, 0,
                        ProtocolNumbers.Tcp, rule.Action, RuleStatus.Inactive, TimeSpan.FromMinutes(60));
                else
                    enforcer.Remove(rule.Id);
            });

            Assert.HasCount(1, enforcer.GetAllRules());
            Assert.AreEqual(RuleStatus.Active, enforcer.GetById(rule.Id)!.Status);
            Assert.Contains(rule.Name, enforcer.WindowsRules);
        }

        [TestMethod]
        public void FailedExpiryCleanup_ShouldKeepRuleActiveAndRetry()
        {
            var clock = new FakeTimeProvider();
            var (enforcer, _) = CreateEnforcer(clock);
            var alert = CreateAlert();
            var rule = enforcer.Apply(Decision(alert, PolicyAction.BlockInboundIp), "P-1", alert.Id, AttackTypes.DoS, TimeSpan.FromMinutes(60));
            enforcer.WindowsRules.Add(rule.Name);
            clock.Advance(TimeSpan.FromMinutes(61));
            enforcer.FailRemoval = true;

            Assert.AreEqual(0, enforcer.RemoveExpired());
            Assert.AreEqual(RuleStatus.Active, enforcer.GetById(rule.Id)!.Status);
            Assert.Contains(rule.Name, enforcer.WindowsRules);

            enforcer.FailRemoval = false;
            Assert.AreEqual(1, enforcer.RemoveExpired());
            Assert.AreEqual(RuleStatus.Expired, enforcer.GetById(rule.Id)!.Status);
            Assert.IsEmpty(enforcer.WindowsRules);
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
            public bool FailRemoval { get; set; }

            public TestFirewallEnforcer(FakeRuleRepository repository, FakeTimeProvider clock)
                : base(repository, Options.Create(new FirewallOptions { DryRun = true }),
                    new FirewallRuntimeState(dryRun: true), clock, NullLogger<WindowsFirewallEnforcer>.Instance)
            {
            }

            protected override void RemoveWindowsRule(string ruleName)
            {
                if (FailRemoval) throw new InvalidOperationException("Simulated Windows rule removal failure.");
                WindowsRules.Remove(ruleName);
            }
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

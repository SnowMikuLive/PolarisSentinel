using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Application;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.FirewallEnforement;
using PolarisSentinel.PolicyDecision;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class PolicyToFirewallChainTests
    {
        [TestMethod]
        public void Alert_MatchedPolicy_ShouldCreateFirewallRule()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var pipeline = CreatePipeline(clock, firewall);

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.50", AttackTypes.DoS), CreatePolicy());

            Assert.AreEqual(PolicyAction.Block, decision.Action);
            Assert.HasCount(1, firewall.GetAllRules());

            var rule = firewall.GetAllRules()[0];
            Assert.AreEqual("203.0.113.50", rule.SourceIp);
            Assert.AreEqual(PolicyAction.Block, rule.Action);
            Assert.IsTrue(rule.Enabled);
        }

        //规则须关联触发告警与决策策略。
        //The rule must reference both the triggering alert and deciding policy.
        [TestMethod]
        public void Alert_RuleShouldLinkAlertIdAndPolicyId()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var pipeline = CreatePipeline(clock, firewall);
            var policy = CreatePolicy();
            policy.Id = "P-7";

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.55", AttackTypes.DoS), policy);

            var rule = firewall.GetAllRules()[0];
            Assert.AreEqual(decision.Id, rule.AlertId);
            Assert.AreEqual("P-7", rule.PolicyId);
        }

        //告警须先于规则提交（AlertId外键）。
        //The alert must be committed before the rule (AlertId FK).
        [TestMethod]
        public void Alert_ShouldBePersistedBeforeRuleIsCreated()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var unitOfWork = new FakeUnitOfWork();
            var pipeline = CreatePipeline(clock, firewall, unitOfWork);

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.56", AttackTypes.DoS), CreatePolicy());

            var stored = unitOfWork.Alerts.GetByIdAsync(decision.Id).GetAwaiter().GetResult();
            Assert.IsNotNull(stored);
            Assert.HasCount(1, firewall.GetAllRules());
        }

        [TestMethod]
        public void Alert_UnmatchedAttackType_ShouldNotCreateRule()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var pipeline = CreatePipeline(clock, firewall);
            var policy = CreatePolicy();
            policy.MatchAttackTypes = AttackTypes.BruteForce;

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.51", AttackTypes.DoS), policy);

            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.IsEmpty(firewall.GetAllRules());
        }

        [TestMethod]
        public void Alert_UnmatchedProtocol_ShouldNotCreateRule()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var pipeline = CreatePipeline(clock, firewall);
            var policy = CreatePolicy();
            policy.MatchProtocol = ProtocolNumbers.Icmp;

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.52", AttackTypes.DoS), policy);

            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.IsEmpty(firewall.GetAllRules());
        }

        [TestMethod]
        public void Alert_ShouldCreateOneRulePerSourceIp()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var pipeline = CreatePipeline(clock, firewall);
            var policy = CreatePolicy();

            pipeline.ProcessFlow(CreateFlow("203.0.113.60", AttackTypes.DoS), policy);
            pipeline.ProcessFlow(CreateFlow("203.0.113.61", AttackTypes.DoS), policy);
            pipeline.ProcessFlow(CreateFlow("203.0.113.62", AttackTypes.DoS), policy);

            var rules = firewall.GetAllRules();
            Assert.HasCount(3, rules);
            CollectionAssert.AreEquivalent(
                new[] { "203.0.113.60", "203.0.113.61", "203.0.113.62" },
                rules.Select(r => r.SourceIp).ToArray());
        }

        [TestMethod]
        public void Alert_RuleShouldExpireAfterBlockDuration()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var pipeline = CreatePipeline(clock, firewall);
            var policy = CreatePolicy();
            policy.BlockDurationMinutes = 10;

            pipeline.ProcessFlow(CreateFlow("203.0.113.70", AttackTypes.DoS), policy);
            Assert.HasCount(1, firewall.GetAllRules());

            clock.Advance(TimeSpan.FromMinutes(11));
            Assert.AreEqual(1, firewall.RemoveExpired());
            Assert.IsEmpty(firewall.GetAllRules());
        }

        [TestMethod]
        public void Alert_RuleShouldSurviveBeforeExpiry()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var pipeline = CreatePipeline(clock, firewall);
            var policy = CreatePolicy();
            policy.BlockDurationMinutes = 10;

            pipeline.ProcessFlow(CreateFlow("203.0.113.71", AttackTypes.DoS), policy);

            clock.Advance(TimeSpan.FromMinutes(9));
            Assert.AreEqual(0, firewall.RemoveExpired());
            Assert.HasCount(1, firewall.GetAllRules());
        }

        //PreFilter路径：告警ID为32位GUID，规则名PolarisSentinel_Block_{id}。
        //PreFilter path:alert id is 32-char GUID;rule name PolarisSentinel_Block_{id}.
        [TestMethod]
        public void Alert_RuleShouldCarryAlertIdForPreFilter()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var pipeline = CreatePipeline(clock, firewall);

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.80", AttackTypes.DoS), CreatePolicy());

            Assert.IsTrue(Guid.TryParseExact(decision.Id, "N", out _));
            Assert.AreEqual(DetectionSource.PreFilter, decision.Source);
            Assert.AreEqual($"PolarisSentinel_Block_{decision.Id}", decision.RuleName);
            Assert.AreEqual(decision.RuleName, firewall.GetAllRules()[0].Name);
        }

        [TestMethod]
        public void Alert_BlockedSourceIpShouldBeScopedToSourceOnly()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var pipeline = CreatePipeline(clock, firewall);

            pipeline.ProcessFlow(CreateFlow("203.0.113.90", AttackTypes.DoS), CreatePolicy());

            var rule = firewall.GetAllRules()[0];
            Assert.AreEqual("203.0.113.90", rule.SourceIp);
            Assert.AreEqual(string.Empty, rule.DestinationIp);
            Assert.AreEqual(0, rule.DestinationPort);
            Assert.AreEqual(0, rule.SourcePort);
        }

        //同源两次检测各自GUID，不再复用递增序号。
        //Two hits on the same source get distinct GUIDs,not a shared counter.
        [TestMethod]
        public void Alert_SameSourceTwiceShouldCreateRulePerAlert()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var pipeline = CreatePipeline(clock, firewall);
            var policy = CreatePolicy();

            var first = pipeline.ProcessFlow(CreateFlow("203.0.113.100", AttackTypes.DoS), policy);
            clock.Advance(TimeSpan.FromMinutes(1));
            var second = pipeline.ProcessFlow(CreateFlow("203.0.113.100", AttackTypes.DoS), policy);

            Assert.AreNotEqual(first.Id, second.Id);
            var rules = firewall.GetAllRules();
            Assert.HasCount(2, rules);
            Assert.IsTrue(rules.All(r => r.SourceIp == "203.0.113.100"));
        }

        private static WindowsFirewallEnforcer CreateFirewall(FakeTimeProvider clock)
        {
            return new WindowsFirewallEnforcer(new FakeRuleRepository(),
                Options.Create(new FirewallOptions()), clock, NullLogger<WindowsFirewallEnforcer>.Instance);
        }

        private static DetectionPipeline CreatePipeline(FakeTimeProvider clock, WindowsFirewallEnforcer firewall)
        {
            return CreatePipeline(clock, firewall, new FakeUnitOfWork());
        }

        private static DetectionPipeline CreatePipeline(FakeTimeProvider clock, WindowsFirewallEnforcer firewall,
            FakeUnitOfWork unitOfWork)
        {
            var policy = new PolicyEngine(clock, NullLogger<PolicyEngine>.Instance);
            return new DetectionPipeline(new NoopInferenceEngine(), policy, firewall, unitOfWork,
                NullLogger<DetectionPipeline>.Instance);
        }

        private static Policy CreatePolicy() => new()
        {
            Id = "P-1",
            DetectionSource = DetectionSource.PreFilter,
            BlockDurationMinutes = 10,
            RuleSourceIpAction = PolicyAction.Block,
            RuleSourcePortAction = PolicyAction.Allow,
            RuleDestinationIpAction = PolicyAction.Allow,
            RuleDestinationPortAction = PolicyAction.Allow
        };

        private static FlowFeatureVector CreateFlow(string sourceIp, string attackType) => new()
        {
            Features = new float[20],
            SourceIp = sourceIp,
            SourcePort = 44444,
            DestinationIp = "192.168.1.10",
            DestinationPort = 80,
            Protocol = ProtocolNumbers.Tcp,
            FlowStartTime = DateTime.UnixEpoch,
            FlowEndTime = DateTime.UnixEpoch.AddSeconds(1),
            PreFilterVerdict = new PreFilterResult { AttackType = attackType, Confidence = 1f, Reason = "prefilter_syn_flood" }
        };

        private sealed class NoopInferenceEngine : IInferenceEngine
        {
            public Alert Detect(FlowFeatureVector flow) => new()
            {
                SourceIp = flow.SourceIp,
                DestinationIp = flow.DestinationIp,
                AttackType = AttackTypes.Benign,
                Confidence = 0f,
                Source = DetectionSource.None,
                Reason = string.Empty
            };
        }
    }
}

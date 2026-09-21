using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Application;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.FirewallEnforement;
using PolarisSentinel.PolicyDecision;
using Microsoft.Extensions.Options;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class PreFilterDetectionTests
    {
        #region Pipeline Tests

        // A pre-filter verdict is treated like a model detection and blocks without confidence.
        [TestMethod]
        public void PreFilterVerdict_ShouldBlockWithoutConfidence()
        {
            var clock = new FakeTimeProvider();
            var firewall = CreateFirewall(clock);
            var pipeline = CreatePipeline(new Alert
            {
                SourceIp = "203.0.113.9",
                DestinationIp = "192.168.1.10",
                AttackType = AttackTypes.SynFlood,
                Confidence = 0f,
                Source = DetectionSource.PreFilter,
                Reason = "prefilter_syn_flood"
            }, clock, firewall);

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.9"));

            Assert.AreEqual(PolicyAction.Block, decision.Action);
            Assert.AreEqual(DetectionSource.PreFilter, decision.Source);
            Assert.AreEqual("prefilter_block", decision.Reason);
            Assert.HasCount(1, firewall.GetAllRules());
        }

        // Pre-filter attack ids use the PF tag.
        [TestMethod]
        public void PreFilterVerdict_ShouldUsePfAlertId()
        {
            var clock = new FakeTimeProvider();
            var pipeline = CreatePipeline(new Alert
            {
                SourceIp = "203.0.113.9",
                DestinationIp = "192.168.1.10",
                AttackType = AttackTypes.PortScan,
                Confidence = 0f,
                Source = DetectionSource.PreFilter,
                Reason = "prefilter_port_scan"
            }, clock, CreateFirewall(clock));

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.9"));

            Assert.StartsWith("A-PF-", decision.Id);
        }

        // Allowlisted addresses downgrade a pre-filter block to Monitor.
        [TestMethod]
        public void PreFilterVerdict_AllowlistedAddress_ShouldMonitor()
        {
            var clock = new FakeTimeProvider();
            var settings = new UserSettings { Allowlist = "203.0.113.9" };
            var firewall = CreateFirewall(clock);
            var pipeline = CreatePipeline(new Alert
            {
                SourceIp = "203.0.113.9",
                DestinationIp = "192.168.1.10",
                AttackType = AttackTypes.SynFlood,
                Confidence = 0f,
                Source = DetectionSource.PreFilter,
                Reason = "prefilter_syn_flood"
            }, clock, firewall, settings);

            var decision = pipeline.ProcessFlow(CreateFlow("203.0.113.9"));

            Assert.AreEqual(PolicyAction.Monitor, decision.Action);
            Assert.IsEmpty(firewall.GetAllRules());
        }

        // The verdict factory copies the 5-tuple and marks the source as PreFilter.
        [TestMethod]
        public void FromPreFilterVerdict_ShouldBuildPreFilterAlert()
        {
            var flow = CreateFlow("203.0.113.9");
            var alert = DetectionPipeline.FromPreFilterVerdict(flow, new PreFilterResult
            {
                AttackType = AttackTypes.SynFlood,
                Confidence = 1f,
                Reason = "prefilter_syn_flood"
            });

            Assert.AreEqual(DetectionSource.PreFilter, alert.Source);
            Assert.AreEqual(AttackTypes.SynFlood, alert.AttackType);
            Assert.AreEqual(flow.SourceIp, alert.SourceIp);
            Assert.AreEqual(flow.DestinationIp, alert.DestinationIp);
        }

        #endregion

        #region Helper Methods

        private static WindowsFirewallEnforcer CreateFirewall(FakeTimeProvider clock)
        {
            return new WindowsFirewallEnforcer(Options.Create(new FirewallOptions()),
                clock, NullLogger<WindowsFirewallEnforcer>.Instance);
        }

        private static DetectionPipeline CreatePipeline(Alert detection, FakeTimeProvider clock,
            WindowsFirewallEnforcer firewall, UserSettings? settings = null)
        {
            var policy = new PolicyEngine(() => settings ?? new UserSettings(), clock,
                NullLogger<PolicyEngine>.Instance);
            return new DetectionPipeline(new FixedInferenceEngine(detection), policy, firewall,
                60, NullLogger<DetectionPipeline>.Instance);
        }

        private static FlowFeatureVector CreateFlow(string sourceIp)
        {
            return new FlowFeatureVector
            {
                Features = new float[20],
                SourceIp = sourceIp,
                SourcePort = 12345,
                DestinationIp = "192.168.1.10",
                DestinationPort = 80,
                Protocol = 6,
                FlowStartTime = DateTime.UnixEpoch,
                FlowEndTime = DateTime.UnixEpoch.AddSeconds(1)
            };
        }

        // Returns a fresh copy of the fixed detection because the policy engine mutates in place.
        private class FixedInferenceEngine : IInferenceEngine
        {
            private readonly Alert _result;

            public FixedInferenceEngine(Alert result)
            {
                _result = result;
            }

            public Alert Detect(FlowFeatureVector flow)
            {
                return new Alert
                {
                    SourceIp = _result.SourceIp,
                    SourcePort = _result.SourcePort,
                    DestinationIp = _result.DestinationIp,
                    DestinationPort = _result.DestinationPort,
                    Protocol = _result.Protocol,
                    AttackType = _result.AttackType,
                    Confidence = _result.Confidence,
                    Source = _result.Source,
                    DetectedAt = _result.DetectedAt,
                    Reason = _result.Reason
                };
            }
        }

        #endregion
    }
}

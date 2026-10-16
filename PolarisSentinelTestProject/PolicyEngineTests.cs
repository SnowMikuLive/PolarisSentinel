using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;
using PolarisSentinel.PolicyDecision;
using Decision = PolarisSentinel.Core.Models.PolicyDecision;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class PolicyEngineUnitTest
{
    [TestMethod]
    public void EvaluateMatchingPolicyShouldBlock()
    {
        var decision = Evaluate(CreateAlert(), CreatePolicy());

        Assert.AreEqual(PolicyAction.BlockInboundIp, decision.Action);
        Assert.AreEqual("policy_block", decision.Reason);
        Assert.AreEqual("P-1", decision.PolicyId);
    }

    [TestMethod]
    public void EvaluateNonMatchingPolicyShouldMonitor()
    {
        var disabled = CreatePolicy();
        disabled.IsEnabled = false;
        var disabledDecision = Evaluate(CreateAlert(), disabled);

        var sourceMismatch = Evaluate(CreateAlert(source: DetectionSource.RandomForest), CreatePolicy(source: DetectionSource.HeuristicBased));
        var typeMismatch = Evaluate(CreateAlert(attackType: AttackTypes.DoS), CreatePolicy(attackType: AttackTypes.PortScan));

        Assert.AreEqual("no_matching_policy", disabledDecision.Reason);
        Assert.AreEqual("no_matching_policy", sourceMismatch.Reason);
        Assert.AreEqual("no_matching_policy", typeMismatch.Reason);
    }

    #region Helper Methods

    private static Decision Evaluate(Alert alert, params Policy[] policies)
    {
        var engine = new PolicyEngine(NullLogger<PolicyEngine>.Instance);
        return engine.Evaluate(alert, policies);
    }

    private static Policy CreatePolicy(
        string id = "P-1",
        DetectionSource? source = null,
        string? attackType = null,
        PolicyAction action = PolicyAction.BlockInboundIp) => new()
    {
        Id = id,
        Name = id,
        UserId = "admin",
        DetectionSource = source,
        AttackType = attackType,
        Action = action,
        BlockDurationMinutes = 60,
        Priority = 100,
        IsEnabled = true,
        CreatedAt = new DateTime(2026, 1, 1),
        UpdatedAt = new DateTime(2026, 1, 1)
    };

    private static Alert CreateAlert(
        float? confidence = 0.99f,
        string attackType = AttackTypes.DoS,
        DetectionSource source = DetectionSource.RandomForest) => new()
    {
        DetectionSource = source,
        AttackType = attackType,
        ConfidenceScore = confidence,
        SourceIp = "203.0.113.66",
        DestinationIp = "192.168.1.10",
        DestinationPort = 80,
        Protocol = ProtocolNumbers.Tcp
    };

    #endregion
}

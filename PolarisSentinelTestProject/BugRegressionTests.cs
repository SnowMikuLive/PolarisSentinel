using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using PolarisSentinel.Application;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Core.Services;
using PolarisSentinel.FirewallEnforement;
using PolarisSentinel.Web.Controllers;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class BugRegressionTests
{
    [TestMethod]
    [DataRow(true, true, PolicyAction.BlockInboundIp)]
    [DataRow(false, true, PolicyAction.BlockInboundIp)]
    [DataRow(true, false, PolicyAction.BlockInboundIp)]
    [DataRow(true, true, PolicyAction.BlockOutboundIp)]
    [DataRow(true, true, PolicyAction.BlockInboundPort)]
    public void Cache_UsesExecutedInboundBlocks(bool enabled, bool succeeds, PolicyAction action)
    {
        var blocked = new BlockedTrafficState();
        var gateway = new FakeFirewallGateway { IsEnabled = enabled, ApplySucceeds = succeeds };
        var enforcer = Enforcer(gateway, blocked);
        var rule = enforcer.Apply(Decision(action), null, null, null, TimeSpan.FromMinutes(1));
        Assert.AreEqual(enabled && succeeds && action == PolicyAction.BlockInboundIp, blocked.IsBlocked("203.0.113.10"));
        Assert.IsFalse(blocked.IsBlocked("192.0.2.10"));
        gateway.IsEnabled = false;
        enforcer.Remove(rule.Id);
        Assert.AreEqual(0, blocked.Count);
    }

    [TestMethod]
    public void ExpiredRemovalFailure_RetainsBlockUntilRetry()
    {
        var blocked = new BlockedTrafficState();
        var gateway = new FakeFirewallGateway();
        var clock = new FakeTimeProvider();
        var enforcer = Enforcer(gateway, blocked, clock: clock);
        enforcer.Apply(Decision(), null, null, null, TimeSpan.FromMinutes(1));
        clock.Advance(TimeSpan.FromMinutes(2));
        gateway.IsEnabled = false;
        gateway.FailRemoval = true;
        Assert.AreEqual(0, enforcer.RemoveExpired());
        Assert.IsTrue(blocked.IsBlocked("203.0.113.10"));
        gateway.FailRemoval = false;
        Assert.AreEqual(1, enforcer.RemoveExpired());
        Assert.AreEqual(0, blocked.Count);
    }

    [TestMethod]
    public void InactiveCreation_NeverAppliesRule()
    {
        var gateway = new FakeFirewallGateway();
        var enforcer = Enforcer(gateway, new BlockedTrafficState());
        var service = new RuleManagementService(enforcer, new FakeUnitOfWork());
        var result = service.Create(new Rule { SourceIp = "203.0.113.10", DestinationIp = "192.0.2.10",
            Action = PolicyAction.BlockInboundIp, Status = RuleStatus.Inactive }, null, null, null, null);
        Assert.AreEqual(RuleStatus.Inactive, result.Status);
        Assert.IsEmpty(gateway.Applied);
    }

    [TestMethod]
    public void AddressLimit_DoesNotRejectPortRules()
    {
        var rules = new FakeRuleRepository();
        for (int i = 0; i < 500; i++) rules.Add(new Rule { Id = $"R-{i + 1}", Name = $"existing-{i}", Action = PolicyAction.BlockInboundIp });
        var enforcer = Enforcer(new FakeFirewallGateway(), new BlockedTrafficState(), rules);
        var rule = enforcer.Apply(Decision(PolicyAction.BlockInboundPort), null, null, null, TimeSpan.FromMinutes(1));
        Assert.AreEqual(PolicyAction.BlockInboundPort, rule.Action);
        Assert.ThrowsExactly<InvalidOperationException>(() => enforcer.Apply(Decision(), null, null, null, TimeSpan.FromMinutes(1)));
    }

    [TestMethod]
    public void MissingIfAndInvalidSavedModel_FallBackToRf_RejectInvalidSelections()
    {
        var settings = new Settings();
        settings.Value.ModelCombination = "999";
        var models = new ModelCombinationService(new Rf(), null, settings: settings);
        Assert.AreEqual(ModelCombination.RandomForestOnly, models.ActiveCombination);
        Assert.HasCount(1, models.AvailableCombinations);
        Assert.AreEqual(AttackTypes.Benign, models.Run(new FlowFeatureVector { Features = new float[20],
            SourceIp = "203.0.113.10", SourcePort = 50000, DestinationIp = "192.0.2.10", DestinationPort = 443,
            Protocol = 6, FlowStartTime = DateTime.UnixEpoch, FlowEndTime = DateTime.UnixEpoch.AddSeconds(1) }).AttackType);
        Assert.ThrowsExactly<ArgumentException>(() => models.SetActiveCombination((ModelCombination)999));
        Assert.ThrowsExactly<ArgumentException>(() => models.SetActiveCombination(ModelCombination.IsolationForestOnly));
        Assert.AreEqual(ModelCombination.RandomForestOnly, models.ActiveCombination);
    }

    [TestMethod]
    public void RuleEdit_UsesRouteIdAndUpdatesCache()
    {
        var blocked = new BlockedTrafficState();
        var enforcer = Enforcer(new FakeFirewallGateway(), blocked);
        var existing = enforcer.Apply(Decision(), null, null, null, TimeSpan.FromMinutes(1));
        var controller = new RulesController(enforcer, new RuleManagementService(enforcer, new FakeUnitOfWork()));
        controller.TempData = new TempDataDictionary(new DefaultHttpContext(), new TempDataProvider());
        var edited = new Rule { SourceIp = "203.0.113.20", DestinationIp = "192.0.2.10", Protocol = 6,
            Action = PolicyAction.BlockInboundIp, Status = RuleStatus.Active };
        var result = controller.Edit(existing.Id, edited, 5, "minutes");
        Assert.IsInstanceOfType<RedirectToActionResult>(result);
        Assert.IsFalse(blocked.IsBlocked("203.0.113.10"));
        Assert.IsTrue(blocked.IsBlocked("203.0.113.20"));
    }

    [TestMethod]
    public void ArtifactResolution_PrefersConfiguredModel()
    {
        string root = Path.Combine(Path.GetTempPath(), "PolarisArtifactTest-" + Guid.NewGuid());
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "ml", "artifacts"));
            File.WriteAllText(Path.Combine(root, "ml", "artifacts", "rf_model.onnx"), "bundled");
            string custom = Path.Combine(root, "custom.onnx");
            File.WriteAllText(custom, "custom");
            var type = typeof(DashboardController).Assembly.GetType("PolarisSentinel.Web.Startup.PrerequisiteCheck")!;
            var method = type.GetMethod("ResolveArtifactPath", BindingFlags.NonPublic | BindingFlags.Static)!;
            Assert.AreEqual(custom, method.Invoke(null, new object[] { root, custom, "rf_model.onnx" }));
        }
        finally
        {
            // Only delete the unique directory created by this test.
            Assert.IsTrue(Path.GetFullPath(root).StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase));
            Directory.Delete(root, recursive: true);
        }
    }

    internal static WindowsFirewallEnforcer Enforcer(FakeFirewallGateway gateway, BlockedTrafficState blocked,
        FakeRuleRepository? rules = null, FakeTimeProvider? clock = null) => new(rules ?? new FakeRuleRepository(), gateway,
            new FirewallRuntimeState(true), clock ?? new FakeTimeProvider(), NullLogger<WindowsFirewallEnforcer>.Instance, blocked);

    internal static PolicyDecision Decision(PolicyAction action = PolicyAction.BlockInboundIp) => new()
    {
        Action = action,
        Alert = new Alert { SourceIp = "203.0.113.10", DestinationIp = "192.0.2.10", DestinationPort = 443,
            Protocol = ProtocolNumbers.Tcp, AttackType = AttackTypes.DoS }
    };

    private sealed class Rf : IRandomForestModel
    {
        public InferenceResult Classify(FlowFeatureVector flow) => InferenceResult.Benign();
        public bool ExceedsThreshold(InferenceResult result) => false;
        public float BenignProbability(FlowFeatureVector flow) => 1;
    }
    private sealed class Settings : IUserSettingsStore
    {
        public UserSettings Value { get; } = new();
        public UserSettings Read() => Value;
        public void Update(Action<UserSettings> mutate) => mutate(Value);
    }

    private sealed class TempDataProvider : ITempDataProvider
    {
        public IDictionary<string, object> LoadTempData(HttpContext context) => new Dictionary<string, object>();
        public void SaveTempData(HttpContext context, IDictionary<string, object> values) { }
    }
}

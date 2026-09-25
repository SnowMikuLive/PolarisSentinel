using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using PolarisSentinel.Application;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Web.Controllers;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Identity;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;
using PolarisSentinel.DataAccess.Data;
using PolarisSentinel.DataAccess.Repository;
using PolarisSentinel.FirewallEnforement;
using PolarisSentinel.PolicyDecision;

namespace PolarisSentienlUnitTestProject;

//LocalDB集成：GUID主键、迁移升级、不兼容历史保护（需POLARIS_LOCALDB_TESTS=1）。
//LocalDB integration:GUID ids,migration upgrade,and bad-history guard (set POLARIS_LOCALDB_TESTS=1).
[TestClass]
public class DatabaseStartupTests
{
    private string _databaseName = string.Empty;
    private ServiceProvider? _services;

    //仅显式启用时运行，每个测试使用独立临时库。
    //Opt in with POLARIS_LOCALDB_TESTS=1;each test uses its own database.
    [TestInitialize]
    public void Setup()
    {
        if (Environment.GetEnvironmentVariable("POLARIS_LOCALDB_TESTS") != "1")
        {
            Assert.Inconclusive("Set POLARIS_LOCALDB_TESTS=1 to run the LocalDB integration tests.");
        }
        _databaseName = "PolarisSentinel_Test_" + Guid.NewGuid().ToString("N");
        //与Web的AddDefaultIdentity使用相同的键长度。
        //Match the Web application's AddDefaultIdentity key length.
        _services = new ServiceCollection()
            .Configure<IdentityOptions>(options => options.Stores.MaxLengthForKeys = 128)
            .BuildServiceProvider();
    }

    [TestCleanup]
    public async Task Cleanup()
    {
        if (_databaseName.StartsWith("PolarisSentinel_Test_", StringComparison.Ordinal))
        {
            await using var db = OpenDatabase();
            await db.Database.EnsureDeletedAsync();
        }
        if (_services != null) await _services.DisposeAsync();
    }

    #region GUID与并发

    [TestMethod]
    public async Task NewDatabase_ConcurrentServicesAndRestart_ShouldSaveUniqueIds()
    {
        await using var db = OpenDatabase();
        await SentinelDbInitializer.MigrateDatabaseAsync(db);

        //独立PolicyEngine/上下文模拟并发与“重启”后仍唯一。
        //Separate engines and DbContexts simulate concurrency and restart uniqueness.
        var ids = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => SaveDetection()));
        var restartedId = await SaveDetection();
        Assert.HasCount(8, ids.Distinct().ToArray());
        Assert.IsFalse(ids.Contains(restartedId));
        Assert.AreEqual(9, await db.Alerts.CountAsync());
        Assert.AreEqual(9, await db.Rules.CountAsync());

        var removed = await db.Rules.FirstAsync();
        db.Rules.Remove(removed);
        await db.SaveChangesAsync();
        await SaveDetection();
        Assert.IsFalse(await db.Rules.AnyAsync(r => r.Id == removed.Id));
        Assert.AreEqual(9, await db.Rules.CountAsync());
    }

    #endregion

    #region 迁移升级

    [TestMethod]
    public async Task ExistingDatabase_Upgrade_ShouldKeepAlerts()
    {
        await using var db = OpenDatabase();
        await db.GetService<IMigrator>().MigrateAsync("20260921064316_InitialCreate");
        var oldAlert = CreateAlert();
        oldAlert.Id = "A-RF-1";
        db.Alerts.Add(oldAlert);
        await db.SaveChangesAsync();
        await db.Database.ExecuteSqlRawAsync("""
            INSERT INTO [Rules] ([Id], [Name], [AlertId], [Action], [SourceIp], [SourcePort],
                [DestinationIp], [DestinationPort], [Protocol], [Enabled], [CreatedAt], [UpdatedAt])
            VALUES ('R-1', 'PolarisSentinel_Block_A-RF-1', 'A-RF-1', 'Block', '203.0.113.66', 12345,
                '192.168.1.10', 80, 6, 1, '2026-09-21', '2026-09-21')
            """);

        await SentinelDbInitializer.MigrateDatabaseAsync(db);
        await SentinelDbInitializer.MigrateDatabaseAsync(db);
        await SaveDetection();

        Assert.AreEqual(2, await db.Alerts.CountAsync());
        Assert.AreEqual("203.0.113.66", (await db.Alerts.SingleAsync(a => a.Id == "A-RF-1")).SourceIp);
        var oldRule = await db.Rules.SingleAsync(r => r.Id == "R-1");
        Assert.AreEqual("A-RF-1", oldRule.AlertId);
        Assert.IsTrue(oldRule.IsBlockRule);
        Assert.IsFalse((await db.Database.GetPendingMigrationsAsync()).Any());
    }

    #endregion

    #region 不兼容历史

    [TestMethod]
    public async Task DifferentMigrationHistory_ShouldStopAndKeepData()
    {
        await using var db = OpenDatabase();
        await SentinelDbInitializer.MigrateDatabaseAsync(db);
        var id = await SaveDetection();
        await db.Database.ExecuteSqlRawAsync(
            "INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion]) VALUES ('20260920052944_InitialCreate', '10.0.11')");

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => SentinelDbInitializer.MigrateDatabaseAsync(db));

        Assert.Contains("different migration history", error.Message);
        Assert.IsTrue(await db.Alerts.AnyAsync(a => a.Id == id));
        Assert.AreEqual(1, await db.Rules.CountAsync());
    }

    #endregion

    // 页面保存后重新读库，验证下一条流使用新策略。
    // Save through the page controller, then reload for the next flow.
    [TestMethod]
    public async Task PolicyPage_Edit_ShouldChangeNextDecision()
    {
        await using (var db = OpenDatabase())
        {
            await SentinelDbInitializer.MigrateDatabaseAsync(db);
            Assert.IsTrue((await db.Policies.FindAsync("P-5"))!.Enabled);
        }

        foreach (var step in new[] { (0.99f, true), (0.80f, true), (0.80f, false) })
        {
            await using (var db = OpenDatabase())
            {
                var http = new DefaultHttpContext();
                var controller = new PoliciesController(new UnitOfWork(db))
                {
                    ControllerContext = new ControllerContext { HttpContext = http },
                    TempData = new TempDataDictionary(http, new TestTempDataProvider())
                };
                var edited = new Policy
                {
                    Enabled = step.Item2,
                    DetectionSource = DetectionSource.RandomForest,
                    RfConfidenceThreshold = step.Item1,
                    BlockDurationMinutes = 7
                };
                var saved = await controller.Edit("P-5", edited, CancellationToken.None);
                Assert.IsInstanceOfType<RedirectToActionResult>(saved);
            }

            // 新上下文代表下一次抓包回调。
            // A fresh context represents the next capture callback.
            await using (var db = OpenDatabase())
            {
                var uow = new UnitOfWork(db);
                var policies = await uow.Policies.GetAllAsync();
                var firewall = new WindowsFirewallEnforcer(uow.Rules,
                    Options.Create(new FirewallOptions { DryRun = true }), TimeProvider.System,
                    NullLogger<WindowsFirewallEnforcer>.Instance);
                var pipeline = new DetectionPipeline(new TestInference(),
                    new PolicyEngine(TimeProvider.System, NullLogger<PolicyEngine>.Instance),
                    firewall, uow, NullLogger<DetectionPipeline>.Instance);
                var decision = pipeline.ProcessFlow(new FlowFeatureVector
                {
                    Features = new float[20], SourceIp = "203.0.113.66", SourcePort = 12345,
                    DestinationIp = "192.168.1.10", DestinationPort = 80, Protocol = 6,
                    FlowStartTime = DateTime.Now, FlowEndTime = DateTime.Now
                }, policies);
                bool shouldBlock = step.Item2 && step.Item1 <= 0.95f;
                Assert.AreEqual(shouldBlock ? PolicyAction.Block : PolicyAction.Monitor, decision.Action);
                Assert.IsTrue(await db.Alerts.AnyAsync(a => a.Id == decision.Id));
                if (shouldBlock)
                {
                    var rule = await db.Rules.SingleAsync(r => r.AlertId == decision.Id);
                    Assert.AreEqual("P-5", rule.PolicyId);
                    Assert.AreEqual(TimeSpan.FromMinutes(7), rule.ExpiresAt - rule.CreatedAt);
                }
                else
                    Assert.IsFalse(await db.Rules.AnyAsync(r => r.AlertId == decision.Id));
            }
        }
    }

    private class TestInference : IInferenceEngine
    {
        public Alert Detect(FlowFeatureVector flow) => CreateAlert();
    }

    private class TestTempDataProvider : ITempDataProvider
    {
        public IDictionary<string, object> LoadTempData(HttpContext context) => new Dictionary<string, object>();
        public void SaveTempData(HttpContext context, IDictionary<string, object> values) { }
    }

    private SentinelDbContext OpenDatabase()
    {
        var options = new DbContextOptionsBuilder<SentinelDbContext>()
            .UseApplicationServiceProvider(_services!)
            .UseSqlServer($"Server=(localdb)\\MSSQLLocalDB;Database={_databaseName};Trusted_Connection=True;TrustServerCertificate=True")
            .Options;
        return new SentinelDbContext(options);
    }

    private async Task<string> SaveDetection()
    {
        await using var db = OpenDatabase();
        var engine = new PolicyEngine(TimeProvider.System, NullLogger<PolicyEngine>.Instance);
        var decision = engine.Evaluate(CreateAlert(), new Policy { Id = "P-5", RfConfidenceThreshold = 0.6f });
        db.Alerts.Add(decision);
        await db.SaveChangesAsync();

        var firewall = new WindowsFirewallEnforcer(new RuleRepository(db),
            Options.Create(new FirewallOptions { DryRun = true }), TimeProvider.System,
            NullLogger<WindowsFirewallEnforcer>.Instance);
        var rule = firewall.Block(decision.SourceIp, 12345, decision.DestinationIp, 80, 6,
            PolicyAction.Block, decision.Id, "P-5", AttackTypes.DoS, TimeSpan.FromMinutes(60));
        await db.SaveChangesAsync();
        Assert.AreEqual(decision.Id, rule.AlertId);
        Assert.AreEqual(32, decision.Id.Length);
        Assert.AreEqual(32, rule.Id.Length);
        return decision.Id;
    }

    private static Alert CreateAlert() => new()
    {
        SourceIp = "203.0.113.66",
        DestinationIp = "192.168.1.10",
        AttackType = AttackTypes.DoS,
        Confidence = 0.95f,
        Source = DetectionSource.RandomForest,
        Reason = "test"
    };
}

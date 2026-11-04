using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.DataAccess.Data;
using PolarisSentinel.Web.Service;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class TrafficHistoryRegressionTests
{
    [TestMethod]
    public async Task FailedSave_RetriesRetainedBatch()
    {
        var repository = new Repository { FailSave = true };
        using var services = Services(repository);
        var state = new DetectionStateService();
        var history = Create(services, state);
        history.Record(new DetectionOutcome { Verdict = TrafficVerdict.Normal });
        await history.FlushAsync();
        Assert.IsEmpty(repository.Saved);
        repository.FailSave = false;
        await history.FlushAsync();
        Assert.HasCount(1, repository.Saved);
    }

    [TestMethod]
    public async Task Clear_WaitsForInflightSave_ThenDeletesOldBatch()
    {
        var repository = new Repository { HoldSave = true };
        using var services = Services(repository);
        var state = new DetectionStateService();
        var history = Create(services, state);
        history.Record(new DetectionOutcome { Verdict = TrafficVerdict.Normal });
        var flush = history.FlushAsync();
        await repository.SaveStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var clear = history.ClearAsync();
        Assert.IsFalse(clear.IsCompleted);
        repository.ReleaseSave.TrySetResult();
        await Task.WhenAll(flush, clear).WaitAsync(TimeSpan.FromSeconds(5));
        await history.FlushAsync();
        Assert.IsEmpty(repository.Saved);
        Assert.IsEmpty(state.GetLiveRecords());
        Assert.AreEqual(0, state.CapturedFlowCount);
    }

    [TestMethod]
    public async Task CaptureStartsOnlyAfterHistoryRestoreCompletes()
    {
        var repository = new Repository { HoldRead = true };
        using var services = Services(repository);
        var state = new DetectionStateService();
        var history = Create(services, state);
        var capture = new Capture();
        var control = new CaptureControlService(capture, NullLogger<CaptureControlService>.Instance);
        using var broadcast = new TrafficBroadcastService(null!, capture, services.GetRequiredService<IServiceScopeFactory>(),
            control, state, history, NullLogger<TrafficBroadcastService>.Instance);
        var start = broadcast.StartAsync(CancellationToken.None);
        await repository.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.IsFalse(capture.Started);
        repository.ReleaseRead.TrySetResult();
        await start.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.IsTrue(capture.Started);
        await broadcast.StopAsync(CancellationToken.None);
    }

    [TestMethod]
    public void Restore_ReplacesCountersAndPreservesDecisionReasons()
    {
        var state = new DetectionStateService();
        var alert = new Alert { Id = "A-RF-1", AttackType = "DoS", SourceIp = "203.0.113.10", DestinationIp = "192.0.2.10",
            Description = "detector explanation" };
        var live = state.Record(new DetectionOutcome { Verdict = TrafficVerdict.Suspicious, Alert = alert,
            Decision = PolicyDecision.Monitor(alert, "no_matching_policy") });
        var saved = DetectionStateService.ToTrafficRecord(live);
        state.Restore(new[] { saved });
        var restored = state.GetLiveRecords().Single();
        Assert.AreEqual(1, state.CapturedFlowCount);
        Assert.AreEqual(1, state.AlertCount);
        Assert.AreEqual(live.Reason, restored.Reason);
        Assert.AreEqual(live.DecisionReason, restored.DecisionReason);
        Assert.AreEqual(live.DecisionText, restored.DecisionText);
    }

    [TestMethod]
    public void MigrationModelAndSql_ContainDecisionFieldsWithoutDatabaseConnection()
    {
        var registrations = new ServiceCollection().AddLogging();
        registrations.AddDbContext<SentinelDbContext>(options =>
            options.UseSqlServer("Server=unused;Database=unused;Trusted_Connection=True"));
        // Match Program's Identity store settings, including its 128-character key lengths.
        registrations.AddDefaultIdentity<ApplicationUser>().AddRoles<IdentityRole>().AddEntityFrameworkStores<SentinelDbContext>();
        using var services = registrations.BuildServiceProvider();
        using var scope = services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
        Assert.IsFalse(context.Database.HasPendingModelChanges(), "Migration snapshot must match the application model.");
        var assembly = context.GetService<IMigrationsAssembly>();
        var migration = assembly.CreateMigration(assembly.Migrations["20261104000000_PersistTrafficDecisionReasons"], context.Database.ProviderName!);
        Assert.IsNotNull(migration.TargetModel.FindEntityType(typeof(TrafficRecord))!.FindProperty(nameof(TrafficRecord.DecisionText)));
        var sql = context.GetService<IMigrator>().GenerateScript("20261016101627_LowerSeededAiPolicyThresholds");
        StringAssert.Contains(sql, "DecisionReason");
        StringAssert.Contains(sql, "DecisionText");
    }

    private static ServiceProvider Services(Repository repository) => new ServiceCollection()
        .AddSingleton<ITrafficRecordRepository>(repository).BuildServiceProvider();

    private static TrafficHistoryService Create(ServiceProvider services, DetectionStateService state) =>
        new(services.GetRequiredService<IServiceScopeFactory>(), state, NullLogger<TrafficHistoryService>.Instance);

    private sealed class Repository : ITrafficRecordRepository
    {
        private List<TrafficRecord> _batch = new();
        public List<TrafficRecord> Saved { get; } = new();
        public bool FailSave { get; set; }
        public bool HoldSave { get; set; }
        public bool HoldRead { get; set; }
        public TaskCompletionSource ReadStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseRead { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource SaveStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseSave { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void AddRange(IEnumerable<TrafficRecord> records) => _batch = records.ToList();
        public async Task<IReadOnlyList<TrafficRecord>> GetSinceAsync(DateTime since, CancellationToken ct = default)
        {
            ReadStarted.TrySetResult();
            if (HoldRead) await ReleaseRead.Task.WaitAsync(ct);
            return Saved.ToArray();
        }
        public Task<int> DeleteBeforeAsync(DateTime cutoff, CancellationToken ct = default) => Task.FromResult(0);
        public Task<int> DeleteAllAsync(CancellationToken ct = default) { int count = Saved.Count; Saved.Clear(); return Task.FromResult(count); }
        public async Task<int> SaveChangesAsync(CancellationToken ct = default)
        {
            SaveStarted.TrySetResult();
            if (HoldSave) await ReleaseSave.Task.WaitAsync(ct);
            if (FailSave) throw new InvalidOperationException("Temporary database failure");
            Saved.AddRange(_batch);
            return _batch.Count;
        }
    }

    private sealed class Capture : ITrafficCaptureService
    {
        public bool Started { get; private set; }
        public IEnumerable<NetworkInterfaceInfo> GetAvailableDevices() => new[]
        {
            new NetworkInterfaceInfo { DeviceName = "fake-device", DisplayName = "fake", IpAddress = "192.0.2.10" }
        };
        public void Start(string name) => Started = true;
        public void Stop() => Started = false;
        public event EventHandler<FlowFeatureVector>? OnFlowCompleted { add { } remove { } }
        public event EventHandler<LiveTrafficSummary>? OnLiveTrafficSummary { add { } remove { } }
    }
}

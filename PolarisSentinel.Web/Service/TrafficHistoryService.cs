using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Service;

// Persists classified flows and restores the current day's history on startup,
// so the dashboard charts and the traffic monitor survive an application restart.
public class TrafficHistoryService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly DetectionStateService _state;
    private readonly ILogger<TrafficHistoryService> _logger;
    private readonly object _lock = new();

    private readonly List<TrafficRecord> _pending = new();

    private static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(5);
    private const int MaxPending = 5000;

    private DateTime _lastFlush = DateTime.Now;

    public TrafficHistoryService(
        IServiceScopeFactory scopeFactory,
        DetectionStateService state,
        ILogger<TrafficHistoryService> logger)
    {
        _scopeFactory = scopeFactory;
        _state = state;
        _logger = logger;
    }

    public async Task RestoreTodayAsync()
    {
        try
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var repository = scope.ServiceProvider.GetRequiredService<ITrafficRecordRepository>();

            var records = await repository.GetSinceAsync(DateTime.Today);
            _state.Restore(records);

            _logger.LogInformation("Restored {Count} traffic record(s) from today", records.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to restore today's traffic history");
        }
    }

    public void DiscardPending()
    {
        lock (_lock)
        {
            _pending.Clear();
        }
    }

    public void Enqueue(TrafficRecord record)
    {
        bool shouldFlush;
        lock (_lock)
        {
            _pending.Add(record);
            shouldFlush = _pending.Count >= MaxPending || DateTime.Now - _lastFlush >= FlushInterval;
        }

        if (shouldFlush)
        {
            _ = FlushAsync();
        }
    }

    public async Task FlushAsync()
    {
        List<TrafficRecord> batch;
        lock (_lock)
        {
            if (_pending.Count == 0)
            {
                return;
            }

            batch = new List<TrafficRecord>(_pending);
            _pending.Clear();
            _lastFlush = DateTime.Now;
        }

        try
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var repository = scope.ServiceProvider.GetRequiredService<ITrafficRecordRepository>();
            repository.AddRange(batch);
            await repository.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist {Count} traffic record(s)", batch.Count);
        }
    }

    public async Task PruneBeforeAsync(DateTime cutoff)
    {
        try
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var repository = scope.ServiceProvider.GetRequiredService<ITrafficRecordRepository>();
            await repository.DeleteBeforeAsync(cutoff);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to prune traffic history before {Cutoff}", cutoff);
        }
    }
}

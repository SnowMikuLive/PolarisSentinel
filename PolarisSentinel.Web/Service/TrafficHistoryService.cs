using System.Diagnostics;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Service;

public class TrafficHistoryService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly DetectionStateService _state;
    private readonly ILogger<TrafficHistoryService> _logger;
    private readonly object _lock = new();
    private readonly SemaphoreSlim _persistenceGate = new(1, 1);

    private readonly List<TrafficRecord> _pending = new();

    private static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(5);
    private const int MaxPending = 5000;

    private long _lastFlushTimestamp = Stopwatch.GetTimestamp();

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

            if (_logger.IsEnabled(LogLevel.Information))
            {
                _logger.LogInformation("Restored {Count} traffic record(s) from today", records.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to restore today's traffic history");
        }
    }

    public async Task ClearAsync(CancellationToken cancellationToken = default)
    {
        await _persistenceGate.WaitAsync(cancellationToken);
        try
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var repository = scope.ServiceProvider.GetRequiredService<ITrafficRecordRepository>();
            await repository.DeleteAllAsync(cancellationToken);
            lock (_lock)
            {
                _pending.Clear();
                _state.Clear();
            }
        }
        finally
        {
            _persistenceGate.Release();
        }
    }

    public DetectionRecord Record(DetectionOutcome outcome)
    {
        bool shouldFlush;
        DetectionRecord record;
        lock (_lock)
        {
            record = _state.Record(outcome);
            _pending.Add(DetectionStateService.ToTrafficRecord(record));
            shouldFlush = _pending.Count >= MaxPending || Stopwatch.GetElapsedTime(_lastFlushTimestamp) >= FlushInterval;
        }

        if (shouldFlush && _persistenceGate.CurrentCount > 0)
        {
            _ = FlushAsync();
        }
        return record;
    }

    public async Task FlushAsync()
    {
        await _persistenceGate.WaitAsync();
        try
        {
            List<TrafficRecord> batch;
            lock (_lock)
            {
                if (_pending.Count == 0) return;
                batch = new List<TrafficRecord>(_pending);
                _pending.Clear();
                _lastFlushTimestamp = Stopwatch.GetTimestamp();
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
                // A failed EF save can leave generated identity values on the entities.
                foreach (var record in batch) record.Id = 0;
                lock (_lock) { _pending.InsertRange(0, batch); }
                _logger.LogError(ex, "Failed to persist {Count} traffic record(s); retained for retry", batch.Count);
            }
        }
        finally
        {
            _persistenceGate.Release();
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

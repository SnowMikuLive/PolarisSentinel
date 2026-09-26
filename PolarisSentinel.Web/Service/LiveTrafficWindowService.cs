using Microsoft.Extensions.Hosting;

namespace PolarisSentinel.Web.Service
{
    // Restores today's traffic history on startup, prunes the in-memory window at
    // midnight, and periodically deletes old rows from the database.
    public class LiveTrafficWindowService : BackgroundService
    {
        // Rows older than this are deleted from the database.
        private static readonly TimeSpan Retention = TimeSpan.FromDays(7);

        private readonly DetectionStateService _state;
        private readonly TrafficHistoryService _history;
        private readonly TimeProvider _timeProvider;

        public LiveTrafficWindowService(
            DetectionStateService state,
            TrafficHistoryService history,
            TimeProvider timeProvider)
        {
            _state = state;
            _history = history;
            _timeProvider = timeProvider;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Bring back today's history before serving traffic.
            await _history.RestoreTodayAsync();

            try
            {
                while (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromMinutes(1), _timeProvider, stoppingToken);

                    var now = _timeProvider.GetLocalNow().DateTime;
                    _state.PruneExpired(now);

                    // Flush anything still pending, then drop rows past the retention window.
                    await _history.FlushAsync();
                    await _history.PruneBeforeAsync(now - Retention);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
            }
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            // Make sure queued records are not lost on shutdown.
            await _history.FlushAsync();
            await base.StopAsync(cancellationToken);
        }
    }
}

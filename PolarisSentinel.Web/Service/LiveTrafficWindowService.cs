using Microsoft.Extensions.Hosting;

namespace PolarisSentinel.Web.Service
{

    public class LiveTrafficWindowService : BackgroundService
    {
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
            try
            {
                while (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromMinutes(1), _timeProvider, stoppingToken);

                    var now = _timeProvider.GetLocalNow().DateTime;
                    _state.PruneExpired(now);

                    await _history.FlushAsync();
                    await _history.PruneBeforeAsync(now - Retention);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            await _history.FlushAsync();
            await base.StopAsync(cancellationToken);
        }
    }
}

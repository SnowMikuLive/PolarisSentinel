using Microsoft.Extensions.Options;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Services;
using PolarisSentinel.FirewallEnforement;

namespace PolarisSentinel.Web.Service
{
    // Remove expired rules at startup and at regular intervals.
    public class FirewallRuleSweeper : BackgroundService
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly TimeProvider _timeProvider;
        private readonly BlockedTrafficState _blocked;
        private readonly TimeSpan _interval;

        public FirewallRuleSweeper(
            IServiceScopeFactory scopeFactory,
            IOptions<FirewallOptions> options,
            TimeProvider timeProvider,
            BlockedTrafficState blocked)
        {
            _scopeFactory = scopeFactory;
            _timeProvider = timeProvider;
            _blocked = blocked;
            int seconds = options.Value.SweepSeconds;
            _interval = TimeSpan.FromSeconds(seconds > 0 ? seconds : 30);
        }

        public override async Task StartAsync(CancellationToken cancellationToken)
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var firewall = scope.ServiceProvider.GetRequiredService<IFirewallEnforcer>();
            firewall.RemoveExpired();
            firewall.Reconcile();
            _blocked.Refresh(firewall.GetAllRules());
            await base.StartAsync(cancellationToken);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {
                while (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(_interval, _timeProvider, stoppingToken);
                    await using var scope = _scopeFactory.CreateAsyncScope();
                    var firewall = scope.ServiceProvider.GetRequiredService<IFirewallEnforcer>();
                    firewall.RemoveExpired();
                    firewall.Reconcile();
                    _blocked.Refresh(firewall.GetAllRules());
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                // End the wait when the service stops.
            }
        }
    }
}

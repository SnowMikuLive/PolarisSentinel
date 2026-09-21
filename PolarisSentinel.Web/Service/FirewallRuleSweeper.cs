using Microsoft.Extensions.Options;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.FirewallEnforement;

namespace PolarisSentinel.Web.Service
{
    // 启动时及定时删除过期规则
    // Remove expired rules at startup and at regular intervals
    public class FirewallRuleSweeper : BackgroundService
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly TimeProvider _timeProvider;
        private readonly TimeSpan _interval;

        public FirewallRuleSweeper(IServiceScopeFactory scopeFactory, IOptions<FirewallOptions> options, TimeProvider timeProvider)
        {
            _scopeFactory = scopeFactory;
            _timeProvider = timeProvider;
            int seconds = options.Value.SweepSeconds;
            _interval = TimeSpan.FromSeconds(seconds > 0 ? seconds : 30);
        }

        public override Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _scopeFactory.CreateScope();
            scope.ServiceProvider.GetRequiredService<IFirewallEnforcer>().RemoveExpired();
            return base.StartAsync(cancellationToken);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {
                while (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(_interval, _timeProvider, stoppingToken);
                    using var scope = _scopeFactory.CreateScope();
                    scope.ServiceProvider.GetRequiredService<IFirewallEnforcer>().RemoveExpired();
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                // 服务停止时结束等待
                // End the wait when the service stops
            }
        }
    }
}

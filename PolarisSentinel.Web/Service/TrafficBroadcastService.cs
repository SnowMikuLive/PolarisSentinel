using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Web.Hubs;

namespace PolarisSentinel.Web.Service
{
    // Capture adapter: runs the detection pipeline, pushes SignalR updates and persists alerts.
    public class TrafficBroadcastService : IHostedService, IDisposable
    {
        private readonly IHubContext<TrafficHub> _hubContext;
        private readonly ITrafficCaptureService _trafficCaptureService;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly CaptureControlService _captureControl;
        private readonly DetectionStateService _state;
        private readonly ILogger<TrafficBroadcastService> _logger;

        public TrafficBroadcastService(
            IHubContext<TrafficHub> hubContext,
            ITrafficCaptureService trafficCaptureService,
            IServiceScopeFactory scopeFactory,
            CaptureControlService captureControl,
            DetectionStateService state,
            ILogger<TrafficBroadcastService> logger)
        {
            _hubContext = hubContext;
            _trafficCaptureService = trafficCaptureService;
            _scopeFactory = scopeFactory;
            _captureControl = captureControl;
            _state = state;
            _logger = logger;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            // Subscribe before starting capture so no early events are missed.
            _trafficCaptureService.OnLiveTrafficSummary += OnLiveTrafficSummaryHandler;
            _trafficCaptureService.OnFlowCompleted += OnFlowCompletedHandler;

            try
            {
                _captureControl.AutoStart();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start traffic capture");
            }
            return Task.CompletedTask;
        }

        private async void OnLiveTrafficSummaryHandler(object? sender, LiveTrafficSummary summary)
        {
            try
            {
                await _hubContext.Clients.All.SendAsync("ReceiveLiveTrafficSummary", summary);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to broadcast live traffic summary");
            }
        }

        // Runs one completed flow through the pipeline and persists the resulting alert.
        private async void OnFlowCompletedHandler(object? sender, FlowFeatureVector flow)
        {
            try
            {
                await using var scope = _scopeFactory.CreateAsyncScope();
                var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
                var pipeline = scope.ServiceProvider.GetRequiredService<IDetectionPipeline>();

                // A background service has no request context, so the owner comes from the seeded policy.
                var policy = await unitOfWork.Policies.GetAllAsync();
                var activePolicy = policy.FirstOrDefault() ?? new Policy();

                var decision = pipeline.ProcessFlow(flow, activePolicy);
                _logger.LogInformation(
                    "Flow {SourceIp}: {AttackType}, {Source}, {Action}, {Reason}",
                    decision.SourceIp, decision.AttackType, decision.Source, decision.Action, decision.Reason);

                var record = new DetectionRecord(
                    decision.Id,
                    decision.SourceIp,
                    decision.DestinationIp,
                    decision.DestinationPort,
                    decision.AttackType,
                    decision.Confidence,
                    decision.Action.ToString(),
                    decision.DecidedAt.ToString("yyyy-MM-dd HH:mm:ss"),
                    decision.Reason,
                    decision.Source.ToString(),
                    decision.RuleName);

                // Push results first so a database error does not stop live updates.
                _state.Record(record);
                await _hubContext.Clients.All.SendAsync("ReceivePolicyDecision", record);

                try
                {
                    unitOfWork.Alerts.Add(decision);
                    await unitOfWork.SaveChangesAsync();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Cannot save detection {AlertId}", decision.Id);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Pipeline failed for flow from {SourceIp}", flow.SourceIp);
            }
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _trafficCaptureService.OnLiveTrafficSummary -= OnLiveTrafficSummaryHandler;
            _trafficCaptureService.OnFlowCompleted -= OnFlowCompletedHandler;
            return Task.CompletedTask;
        }

        public void Dispose()
        {
        }
    }
}

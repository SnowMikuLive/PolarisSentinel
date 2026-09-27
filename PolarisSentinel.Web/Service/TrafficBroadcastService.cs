using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Web.Hubs;

namespace PolarisSentinel.Web.Service
{
    // Capture adapter: runs the detection pipeline, pushes SignalR updates and records dashboard counters.
    public class TrafficBroadcastService : IHostedService, IDisposable
    {
        private readonly IHubContext<TrafficHub> _hubContext;
        private readonly ITrafficCaptureService _trafficCaptureService;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly CaptureControlService _captureControl;
        private readonly DetectionStateService _state;
        private readonly TrafficHistoryService _history;
        private readonly ILogger<TrafficBroadcastService> _logger;

        public TrafficBroadcastService(
            IHubContext<TrafficHub> hubContext,
            ITrafficCaptureService trafficCaptureService,
            IServiceScopeFactory scopeFactory,
            CaptureControlService captureControl,
            DetectionStateService state,
            TrafficHistoryService history,
            ILogger<TrafficBroadcastService> logger)
        {
            _hubContext = hubContext;
            _trafficCaptureService = trafficCaptureService;
            _scopeFactory = scopeFactory;
            _captureControl = captureControl;
            _state = state;
            _history = history;
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

        // Runs one completed flow through the pipeline and records the outcome.
        private async void OnFlowCompletedHandler(object? sender, FlowFeatureVector flow)
        {
            try
            {
                await using var scope = _scopeFactory.CreateAsyncScope();
                var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
                var pipeline = scope.ServiceProvider.GetRequiredService<IDetectionPipeline>();

                var policies = await unitOfWork.Policies.GetEnabledAsync();
                var outcome = pipeline.ProcessFlow(flow, policies);

                var record = _state.Record(outcome);

                // Persist for long-term history so charts survive a restart.
                _history.Enqueue(DetectionStateService.ToTrafficRecord(record));

                // Every classified flow is pushed so the live monitor can show the full window.
                await _hubContext.Clients.All.SendAsync("ReceivePolicyDecision", record);
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

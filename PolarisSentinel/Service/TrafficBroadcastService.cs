using Microsoft.AspNetCore.SignalR;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Web.Hubs;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using PolarisSentinel.Inference;

namespace PolarisSentinel.Web.Service
{
    // 抓包事件适配器：调用检测管线、推送 SignalR、持久化结果
    // Capture adapter: runs detection pipeline, pushes SignalR, persists results
    public class TrafficBroadcastService:IHostedService, IDisposable
    {
        private readonly IHubContext<TrafficHub> _hubContext;
        private readonly ITrafficCaptureService _trafficCaptureService;
        private readonly IDetectionPipeline _pipeline;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly CaptureControlService _captureControl;
        private readonly ILogger<TrafficBroadcastService> _logger;

        private readonly DetectionStateService _state;

        public TrafficBroadcastService(
            IHubContext<TrafficHub> hubContext, 
            ITrafficCaptureService trafficCaptureService,
            IDetectionPipeline pipeline,
            IServiceScopeFactory scopeFactory,
            CaptureControlService captureControl,
            DetectionStateService state,
            ILogger<TrafficBroadcastService> logger
            )
        {
            _hubContext = hubContext;
            _trafficCaptureService = trafficCaptureService;
            _pipeline = pipeline;
            _scopeFactory = scopeFactory;
            _captureControl = captureControl;
            _state = state;
            _logger = logger;
        }

        //Subscribe to event when service starts
        public Task StartAsync(CancellationToken cancellationToken)
        {
            //modify: Subscribe first, then start the traffic capture service to avoid missing any events
            // Subscribe to the OnLiveTrafficSummary event
            _trafficCaptureService.OnLiveTrafficSummary += OnLiveTrafficSummaryHandler;

            //Subscribe to flow completion event for real inference and policy evaluation
            _trafficCaptureService.OnFlowCompleted += OnFlowCompletedHandler;

            //Auto-select a device (Wi-Fi preferred) and start capture.
            try
            {
                _captureControl.AutoStart();
            }
            catch (Exception ex)
            {
                // Log the exception to the debug output
                _logger.LogError(ex, "Failed to start traffic capture");
            }
                return Task.CompletedTask;
        }

        //Handle live traffic summery event
        private async void OnLiveTrafficSummaryHandler(object? sender, LiveTrafficSummary summary)
        {
            try
            {
                await _hubContext.Clients.All.SendAsync("ReceiveLiveTrafficSummary", summary);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to boardcast live traffic summary:{ex.Message}");
            }
        }

        private async void OnFlowCompletedHandler(object? sender, FlowFeatureVector flow)
        {
            try
            {
                // 抓包特征转为模型契约，保留流地址和时间
                // Convert capture features and keep the flow addresses and times
                var modelFlow = new FlowFeatureVector
                {
                    Features = LegacyFeatureAdapter.ToContract(flow.Features),
                    SourceIp = flow.SourceIp,
                    SourcePort = flow.SourcePort,
                    DestinationIp = flow.DestinationIp,
                    DestinationPort = flow.DestinationPort,
                    Protocol = flow.Protocol,
                    FlowStartTime = flow.FlowStartTime,
                    FlowEndTime = flow.FlowEndTime,
                    TotalPackets = flow.TotalPackets,
                    TotalBytes = flow.TotalBytes
                };
                var decision = _pipeline.ProcessFlow(modelFlow);
                _logger.LogInformation(
                    "Flow {SourceIp}: {InputCount}->20 features, {AttackType}, {Source}, {Action}, {Reason}",
                    decision.SourceIp, flow.Features.Length, decision.AttackType,
                    decision.Source, decision.Action, decision.Reason);

                var record = new DetectionRecord(
                    decision.AlertId,
                    decision.SourceIp,
                    flow.DestinationIp,
                    flow.DestinationPort,
                    decision.AttackType,
                    decision.Confidence,
                    decision.Action.ToString(),
                    decision.DecidedAt.ToString("HH:mm:ss"),
                    decision.Reason,
                    decision.Source.ToString(),
                    decision.RuleName);

                // 先推送结果，写库失败不影响实时页面
                // Push results first so a database error does not stop live updates
                _state.Record(record);
                await _hubContext.Clients.All.SendAsync("ReceivePolicyDecision", record);

                //Persist the alert (5-tuple + inference result) in a short-lived scope,
                //because the unit of work depends on a scoped DbContext while this is a singleton.
                try
                {
                    await using (var scope = _scopeFactory.CreateAsyncScope())
                    {
                        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
                        unitOfWork.Alerts.Add(new Alert
                        {
                            SourceIp = flow.SourceIp,
                            SourcePort = flow.SourcePort,
                            DestinationIp = flow.DestinationIp,
                            DestinationPort = flow.DestinationPort,
                            Protocol = flow.Protocol,
                            AttackType = decision.AttackType,
                            Confidence = decision.Confidence,
                            Source = decision.Source,
                            Action = decision.Action,
                            RuleName = decision.RuleName,
                            Reason = decision.Reason,
                            DetectedAt = decision.DecidedAt
                        });
                        await unitOfWork.SaveChangesAsync();
                    }
                }

                catch (Exception ex)
                {
                    _logger.LogError(ex, "Cannot save detection {AlertId}", decision.AlertId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Pipeline failed for flow from {SourceIp}", flow.SourceIp);
            }
        }
        
        public Task StopAsync(CancellationToken cancellationToken)
        {
            // Unsubscribe from the OnLiveTrafficSummary event
            _trafficCaptureService.OnLiveTrafficSummary -= OnLiveTrafficSummaryHandler;

            //add: Unsubscribe from flow completionevent
            _trafficCaptureService.OnFlowCompleted -= OnFlowCompletedHandler;

            //add stop traffic capture service
            _trafficCaptureService.Stop();

            return Task.CompletedTask;
        }
        public void Dispose()
        {
            StopAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
    }
}

using Microsoft.AspNetCore.SignalR;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Web.Hubs;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace PolarisSentinel.Web.Service
{
    // Presentation-layer adapter: subscribes to traffic capture events and pushes
    // results through SignalR. It delegates the detection -> decision -> enforcement
    // pipeline to the application layer (IDetectionPipeline) and persists results
    // through IDetectionRepository. It contains no business logic itself.
    public class TrafficBroadcastService:IHostedService, IDisposable
    {
        private readonly IHubContext<TrafficHub> _hubContext;
        private readonly ITrafficCaptureService _trafficCaptureService;
        private readonly IDetectionPipeline _pipeline;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly CaptureControlService _captureControl;

        //Inject global state service
        private readonly DetectionStateService _state;

        public TrafficBroadcastService(
            IHubContext<TrafficHub> hubContext, 
            ITrafficCaptureService trafficCaptureService,
            IDetectionPipeline pipeline,
            IServiceScopeFactory scopeFactory,
            CaptureControlService captureControl,
            DetectionStateService state
            )
        {
            _hubContext = hubContext;
            _trafficCaptureService = trafficCaptureService;
            _pipeline = pipeline;
            _scopeFactory = scopeFactory;
            _captureControl = captureControl;
            _state = state;
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
                System.Diagnostics.Debug.WriteLine($"Failed to start traffic capture service: {ex.Message}");
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

        //Handle flow completion events: delegate the pipeline to the application layer.
        private async void OnFlowCompletedHandler(object? sender, FlowFeatureVector flow)
        {
            try
            {
                //Run the detection -> decision -> enforcement pipeline.
                var decision = _pipeline.ProcessFlow(flow);

                //Build unified record object
                var record = new DetectionRecord(
                    decision.AlertId,
                    decision.SourceIp,
                    flow.DestinationIp,
                    flow.DestinationPort,
                    decision.AttackType,
                    decision.Confidence,
                    decision.Action.ToString(),
                    decision.DecidedAt.ToString("HH:mm:ss"),
                    decision.Reason);

                //Persist the alert (5-tuple + inference result) in a short-lived scope,
                //because the repository depends on a scoped DbContext while this is a singleton.
                using (var scope = _scopeFactory.CreateScope())
                {
                    var repository = scope.ServiceProvider.GetRequiredService<IAlertRepository>();
                    await repository.AddAsync(new Alert
                    {
                        SourceIp = flow.SourceIp,
                        SourcePort = flow.SourcePort,
                        DestinationIp = flow.DestinationIp,
                        DestinationPort = flow.DestinationPort,
                        Protocol = flow.Protocol,
                        AttackType = decision.AttackType,
                        Confidence = decision.Confidence,
                        Source = DetectionSource.RandomForest,
                        DetectedAt = decision.DecidedAt
                    });
                }

                //Record to global state first
                _state.Record(record);

                //Push policy decision via SignalR
                await _hubContext.Clients.All.SendAsync("ReceivePolicyDecision", record);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Pipeline failed for flow: {ex.Message}");
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

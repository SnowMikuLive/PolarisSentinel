using Microsoft.AspNetCore.SignalR;
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

        //Inject global state service
        private readonly DetectionStateService _state;

        public TrafficBroadcastService(
            IHubContext<TrafficHub> hubContext, 
            ITrafficCaptureService trafficCaptureService,
            IDetectionPipeline pipeline,
            IServiceScopeFactory scopeFactory,
            DetectionStateService state
            )
        {
            _hubContext = hubContext;
            _trafficCaptureService = trafficCaptureService;
            _pipeline = pipeline;
            _scopeFactory = scopeFactory;
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

            //Select the device and start capture automatically.
            try
            {
                var devices = _trafficCaptureService.GetAvailableDevices().ToList();

                //Make the Wi-Fi or Ethernet device as the default capture device if it exists, otherwise use the first available device.
                //d is also the device object , it will check the DisplayName of the device.
                var selectedDevice = devices.FirstOrDefault(d =>
                    d.DisplayName.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase) ||
                    // Check for Ethernet devices
                    d.DisplayName.Contains("Ethernet", StringComparison.OrdinalIgnoreCase))
                    // If no Wi-Fi or Ethernet device is found, select the first available device
                    ?? devices.FirstOrDefault();

                if (selectedDevice != null)
                {
                    //System.Diagnostics.Debug.WriteLine($"Starting capture on:{selectedDevice.DisplayName}");
                    _trafficCaptureService.Start(selectedDevice.DeviceName);
                    //System.Diagnostics.Debug.WriteLine("Traffic capture service started successfully."); ;
                }
                //else
                //{
                //    System.Diagnostics.Debug.WriteLine("No network devices found for capture");
                //}

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

                //Persist the detection event within a short-lived scope, because the
                //repository depends on a scoped DbContext while this service is a singleton.
                using (var scope = _scopeFactory.CreateScope())
                {
                    var repository = scope.ServiceProvider.GetRequiredService<IDetectionRepository>();
                    await repository.AddAsync(new DetectionEvent
                    {
                        SourceIp = decision.SourceIp,
                        DestinationIp = flow.DestinationIp,
                        DestinationPort = flow.DestinationPort,
                        AttackType = decision.AttackType,
                        Confidence = decision.Confidence,
                        Action = decision.Action,
                        Reason = decision.Reason,
                        DecidedAt = decision.DecidedAt
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

using Microsoft.AspNetCore.SignalR;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Web.Hubs;
using Microsoft.Extensions.Hosting;

namespace PolarisSentinel.Web.Service
{
    //Background service to subscribe to traffic capture events and push them through SignalR.
    public class TrafficBroadcastService:IHostedService, IDisposable
    {
        private readonly IHubContext<TrafficHub> _hubContext;
        private readonly ITrafficCaptureService _trafficCaptureService;
        private readonly IInferenceEngine  _inferenceEngine;
        private readonly IPolicyEngine _policyEngine;

        //add inference and policy engines
        public TrafficBroadcastService(
            IHubContext<TrafficHub> hubContext, 
            ITrafficCaptureService trafficCaptureService,
            IInferenceEngine inferenceEngine,
            IPolicyEngine policyEngine
            )
        {
            _hubContext = hubContext;
            _trafficCaptureService = trafficCaptureService;
            _inferenceEngine= inferenceEngine;
            _policyEngine= policyEngine;
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

                //Output the available devices to debug the window
                System.Diagnostics.Debug.WriteLine($"Avaliable devices:{devices.Count}");
                foreach (var device in devices)
                {
                    System.Diagnostics.Debug.WriteLine($"-{device.DisplayName}");
                }

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
                    System.Diagnostics.Debug.WriteLine($"Starting capture on:{selectedDevice.DisplayName}");
                    _trafficCaptureService.Start(selectedDevice.DeviceName);
                    System.Diagnostics.Debug.WriteLine("Traffic capture service started successfully."); ;
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine("No network devices found for capture");
                }

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

        //add: Handle flow completion events. The flow steps are inference to policy to push
        private async void OnFlowCompletedHandler(object? sender, FlowFeatureVector flow)
        {
            try
            {
                //Step 1: Inference
                var detection = _inferenceEngine.Detect(flow);
                //Step 2: Policy evaluation
                var decision = _policyEngine.Evaluate(detection);
                //Step 3: Push policy decision via Su=ignalR
                await _hubContext.Clients.All.SendAsync("ReceivePolicyDecision", new
                { 
                    alertId=decision.AlertId,
                    sourceIp=decision.SourceIp,
                    //Supplement target IP from streams
                    destinationIp=flow.DestinationIp,
                    //Supplementing the target port from the stream
                    destinationPort=flow.DestinationPort,
                    attackType=decision.AttackType,
                    confidence=decision.Confidence,
                    //Action:Ignore/Monitor/Block
                    action=decision.Action.ToString(),
                    decidedAt=decision.DecidedAt.ToString("HH:mm:ss"),
                    reason=decision.Reason
                });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to broadcast live traffic summary: {ex.Message}");
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

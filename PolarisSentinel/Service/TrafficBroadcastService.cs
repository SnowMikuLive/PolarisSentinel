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
        public TrafficBroadcastService(IHubContext<TrafficHub> hubContext, ITrafficCaptureService trafficCaptureService)
        {
            _hubContext = hubContext;
            _trafficCaptureService = trafficCaptureService;
        }

        //Subscribe to event when service starts
        public Task StartAsync(CancellationToken cancellationToken)
        {
            //modify: Subscribe first, then start the traffic capture service to avoid missing any events
            // Subscribe to the OnLiveTrafficSummary event
            _trafficCaptureService.OnLiveTrafficSummary += OnLiveTrafficSummaryHandler;

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
        
        private async void OnLiveTrafficSummaryHandler(object? sender, LiveTrafficSummary summary)
        {
            //add try catch to prevent the process from crashing, if SendAsync fails, it will log the error to the debug output and continue running.
            try
            {
                // Broadcast the live traffic summary to all connected clients
                await _hubContext.Clients.All.SendAsync("ReceiveLiveTrafficSummary", summary);
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

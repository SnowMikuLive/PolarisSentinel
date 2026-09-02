using Microsoft.AspNetCore.SignalR;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Hubs
{
        //Real-time traffic hub
        public class TrafficHub : Hub
        {
            //private readonly ITrafficCaptureService _trafficCaptureService;

            //public TrafficHub(ITrafficCaptureService trafficCaptureService)
            //{
            //    _trafficCaptureService = trafficCaptureService;

            //    //// Subscribe to the OnLiveTrafficSummary event
            //    //_trafficCaptureService.OnLiveTrafficSummary += OnLiveTrafficSummaryHandler;
            //}

            //public override async Task OnConnectedAsync()
            //{
            //// Subscribe to the OnLiveTrafficSummary event
            //_trafficCaptureService.OnLiveTrafficSummary += OnLiveTrafficSummaryHandler;

            ////When a client connects, send the current live traffic summary network interfaces. If ITrafficCaptureService add GetAvaliableDevices(), these line can be avaliable.
            ////var devices = _trafficCaptureService.GetAvailableDevices();
            ////await Clients.Caller.SendAsync("ReceiveAvailableDevices", devices);
            //await base.OnConnectedAsync();
            //}


            ////When client disconnected, just to Unsubscribe it 
            //public override async Task OnDisconnectedAsync(Exception?exception)
            //{
            ////Unsubscribe on discount for preventing the reference
            //_trafficCaptureService.OnLiveTrafficSummary -= OnLiveTrafficSummaryHandler;
            //await base.OnDisconnectedAsync(exception);
            //}

            ////Handle live traffic summary event and send them to all clients
            //private async void OnLiveTrafficSummaryHandler(object? sender, LiveTrafficSummary summary)
            //{
            //    await Clients.All.SendAsync("ReceiveLiveTrafficSummary",summary);
            //}
        }
    }
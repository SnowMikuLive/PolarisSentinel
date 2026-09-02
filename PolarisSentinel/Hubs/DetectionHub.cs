using Microsoft.AspNetCore.SignalR;

namespace PolarisSentinel.Hubs;

//Server-to-client push only; clients subscribe to the "detection" event.
public sealed class DetectionHub : Hub
{
}

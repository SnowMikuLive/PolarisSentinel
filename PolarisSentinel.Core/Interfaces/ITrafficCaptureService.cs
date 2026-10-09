using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface ITrafficCaptureService
{
    IEnumerable<NetworkInterfaceInfo> GetAvailableDevices();


    void Start(string deviceName);

    void Stop();

    event EventHandler<FlowFeatureVector>? OnFlowCompleted;


    event EventHandler<LiveTrafficSummary>? OnLiveTrafficSummary;
}

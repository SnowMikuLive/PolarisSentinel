using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface ITrafficCaptureService
{
    //Get the list about the available network devices on the system
    IEnumerable<NetworkInterfaceInfo> GetAvailableDevices();


    //Starts capturing on the given network interface 
    void Start(string deviceName);

    void Stop();

    // Event that is raised when a flow is completed
    event EventHandler<FlowFeatureVector>? OnFlowCompleted;

    // Event that is raised when a live traffic summary is available

    event EventHandler<LiveTrafficSummary>? OnLiveTrafficSummary;
}

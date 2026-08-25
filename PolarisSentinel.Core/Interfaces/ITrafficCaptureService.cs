using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface ITrafficCaptureService
{
    
    //Starts capturing on the given network interface 
    void Start(string deviceName);

    void Stop();


    event EventHandler<FlowFeatureVector>? OnFlowCompleted;

    event EventHandler<LiveTrafficSummary>? OnLiveTrafficSummary;
}

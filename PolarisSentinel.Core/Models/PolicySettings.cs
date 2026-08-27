namespace PolarisSentinel.Core.Models;


public class PolicySettings
{
    //Minimum Random Forest probability required to treat a prediction as an attack
    public double RfConfidenceThreshold { get; set; } = 0.6;

    //Isolation Forest anomaly score below which a flow is treated as anomalous.
    public double IfAnomalyThreshold { get; set; } = -0.1;

    public int FlowIdleTimeoutMilliseconds { get; set; } = 120000;

    public int PreFilterMinPackets { get; set; } = 3;

    public double AutoBlockConfidenceThreshold { get; set; } = 0.8;
}

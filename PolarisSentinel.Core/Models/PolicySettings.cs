namespace PolarisSentinel.Core.Models;


public class PolicySettings
{
    //Minimum Random Forest probability required to treat a prediction as an attack
    public double RfConfidenceThreshold { get; set; } = 0.6;

    //Isolation Forest anomaly score below which a flow is treated as anomalous.
    public double IfAnomalyThreshold { get; set; } = -0.1;

    //120s aligns with the CICFlowMeter flow timeout used to generate CIC-IDS2017,
    //so live flow segmentation matches the training data distribution.
    public int FlowIdleTimeoutSeconds { get; set; } = 120;

    public int PreFilterMinPackets { get; set; } = 3;

    public double AutoBlockConfidenceThreshold { get; set; } = 0.8;
}

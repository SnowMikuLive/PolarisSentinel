namespace PolarisSentinel.Core.Models;


public class PolicySettings
{
    // 随机森林概率达到此值才视为攻击告警
    // Minimum RF probability required to treat a prediction as an attack
    public double RfConfidenceThreshold { get; set; } = 0.6;

    // 孤立森林异常分数低于此值视为异常；验证集 0.1% 误报预算下测得。
    // 推理引擎实际从 IF ONNX 元数据读取同一值，此处为配置层默认值。
    // IF anomaly score below which a flow is anomalous (0.1% FPR budget on validation).
    // The inference engine reads the same value from IF ONNX metadata; this is the config default.
    public double IfAnomalyThreshold { get; set; } = -0.150806;

    public int FlowIdleTimeoutMilliseconds { get; set; } = 120000;

    public int PreFilterMinPackets { get; set; } = 3;

    public double AutoBlockConfidenceThreshold { get; set; } = 0.8;
}

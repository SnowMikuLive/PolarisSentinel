namespace PolarisSentinel.Core.Models;

// 策略与采集共享配置，绑定 appsettings PolicySettings 节
// Shared policy and capture settings
public class PolicySettings
{
    public double RfConfidenceThreshold { get; set; } = 0.6;

    // IF 默认阈值，推理从 ONNX 读取
    // IF default; inference reads ONNX
    public double IfAnomalyThreshold { get; set; } = -0.150806;

    public int FlowIdleTimeoutMilliseconds { get; set; } = 120000;

    public int PreFilterMinPackets { get; set; } = 3;

    public double AutoBlockConfidenceThreshold { get; set; } = 0.8;

    public int BlockDurationMinutes { get; set; } = 60;

    // 同 IP Block 冷却（秒）
    // Block cooldown per IP (seconds)
    public int DecisionCooldownSeconds { get; set; } = 60;

    // 命中则 Block 降为 Monitor
    // Block downgraded to Monitor on match
    public string[] Allowlist { get; set; } = [];
}

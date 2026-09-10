namespace PolarisSentinel.Core.Models;

// 策略引擎与流量采集的共享配置，通过 appsettings.json 的 PolicySettings 节绑定。
// Shared configuration for the policy engine and traffic capture, bound from PolicySettings in appsettings.json.
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

    // 流空闲超时（毫秒），超过后视为一条流结束
    // Flow idle timeout in milliseconds before a flow is considered closed
    public int FlowIdleTimeoutMilliseconds { get; set; } = 120000;

    // PreFilter 最小包数，低于此值的流不进入模型
    // PreFilter minimum packet count; flows below this never reach the model
    public int PreFilterMinPackets { get; set; } = 3;

    // 置信度达到此值且来源为 RF 已知攻击时，才触发自动封禁
    // Auto-block only when confidence reaches this level on a known RF attack
    public double AutoBlockConfidenceThreshold { get; set; } = 0.8;

    // 防火墙封禁规则的默认持续时间（分钟）
    // Default duration for firewall block rules in minutes
    public int BlockDurationMinutes { get; set; } = 60;

    // 同一源 IP 两次 Block 决策之间的最短间隔（秒），防止重复封禁
    // Minimum seconds between Block decisions for the same source IP
    public int DecisionCooldownSeconds { get; set; } = 60;

    // 用户配置的受保护 IP 或 CIDR 段；命中时 Block 降级为 Monitor
    // User-configured protected IPs or CIDR ranges; Block is downgraded to Monitor on match
    public string[] Allowlist { get; set; } = [];
}

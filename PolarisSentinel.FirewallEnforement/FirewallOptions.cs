namespace PolarisSentinel.FirewallEnforement
{
    // 防火墙执行配置，绑定 appsettings Firewall 节
    // Firewall execution settings bound to appsettings Firewall section
    public class FirewallOptions
    {
        // 默认只操作内存中的规则
        // Use in-memory rules by default
        public bool DryRun { get; set; } = true;

        // Block 决策的默认封禁时长（分钟）
        // Default block duration in minutes for Block decisions
        public int BlockMinutes { get; set; } = 60;

        // 过期规则清扫间隔（秒）
        // Interval in seconds for sweeping expired rules
        public int SweepSeconds { get; set; } = 30;
    }
}

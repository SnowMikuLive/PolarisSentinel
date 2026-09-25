namespace PolarisSentinel.FirewallEnforement
{
    //防火墙执行配置，绑定appsettings Firewall节
    //Firewall execution settings bound to appsettings Firewall section
    public class FirewallOptions
    {
        //默认只操作内存中的规则
        //Use in-memory rules by default
        public bool DryRun { get; set; } = true;

        //过期规则清扫间隔（秒）
        //Interval in seconds for sweeping expired rules
        public int SweepSeconds { get; set; } = 30;
    }
}

namespace PolarisSentinel.FirewallEnforement
{

    public class FirewallOptions
    {
        public bool DryRun { get; set; } = true;

        public int SweepSeconds { get; set; } = 30;
    }
}

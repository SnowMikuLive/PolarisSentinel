namespace PolarisSentinel.FirewallEnforement
{
    // Firewall execution settings bound to the appsettings "Firewall" section.
    public class FirewallOptions
    {
        public bool DryRun { get; set; } = true;

        public int SweepSeconds { get; set; } = 30;
    }
}

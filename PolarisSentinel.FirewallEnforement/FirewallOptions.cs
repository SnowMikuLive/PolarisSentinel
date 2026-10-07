namespace PolarisSentinel.FirewallEnforement
{
    // Firewall execution settings bound to the appsettings "Firewall" section.
    public class FirewallOptions
    {
        // Use in-memory rules only (no real Windows Firewall writes).
        public bool DryRun { get; set; } = true;

        // Interval in seconds for sweeping expired rules.
        public int SweepSeconds { get; set; } = 30;
    }
}

namespace PolarisSentinel.FirewallEnforement
{
    // Live, runtime-toggleable firewall enforcement state. Seeded from FirewallOptions at
    // startup, then changed from the dashboard. Singleton, so a toggle is seen by every
    // enforcer instance created afterwards.
    public sealed class FirewallRuntimeState
    {
        private readonly object _lock = new();
        private bool _dryRun;

        public FirewallRuntimeState(bool dryRun)
        {
            _dryRun = dryRun;
        }

        // True when rules are only recorded, not written to the OS firewall.
        public bool DryRun
        {
            get
            {
                lock (_lock)
                {
                    return _dryRun;
                }
            }
            set
            {
                lock (_lock)
                {
                    _dryRun = value;
                }
            }
        }
    }
}

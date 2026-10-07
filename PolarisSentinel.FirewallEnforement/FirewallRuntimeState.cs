using PolarisSentinel.Core.Interfaces;

namespace PolarisSentinel.FirewallEnforement
{
    // Live, runtime-toggleable firewall enforcement state. Seeded from FirewallOptions at
    // startup, then changed from the dashboard. Singleton, so a toggle is seen by every
    // enforcer instance created afterwards.
    public sealed class FirewallRuntimeState
    {
        private readonly object _lock = new();
        private readonly IUserSettingsStore? _settings;
        private bool _dryRun;

        public FirewallRuntimeState(bool dryRun, IUserSettingsStore? settings = null)
        {
            _settings = settings;
            // A saved user choice wins over the configured default, so it survives a restart.
            _dryRun = settings?.Read().DryRun ?? dryRun;
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

                // Only a user toggle reaches this setter, so this is the setting to persist.
                _settings?.Update(s => s.DryRun = value);
            }
        }
    }
}

using PolarisSentinel.Core.Interfaces;

namespace PolarisSentinel.FirewallEnforement
{

    public sealed class FirewallRuntimeState
    {
        private readonly object _lock = new();
        private readonly IUserSettingsStore? _settings;
        private bool _dryRun;

        public FirewallRuntimeState(bool dryRun, IUserSettingsStore? settings = null)
        {
            _settings = settings;
            _dryRun = settings?.Read().DryRun ?? dryRun;
        }

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

                _settings?.Update(s => s.DryRun = value);
            }
        }
    }
}

using PolarisSentinel.Core.Interfaces;

namespace PolarisSentinel.Core.Services;

// Live, runtime-toggleable heuristic-detection state, mirroring FirewallRuntimeState: seeded
// from the user's saved choice at startup and changed from the dashboard. A singleton, so the
// capture layer and the detection pipeline both see a change immediately. Persisted through
// IUserSettingsStore like the other user settings.
public sealed class DetectionRuntimeState
{
    private readonly object _lock = new();
    private readonly IUserSettingsStore? _settings;
    private bool _heuristicEnabled;

    public DetectionRuntimeState(bool heuristicEnabled, IUserSettingsStore? settings = null)
    {
        _settings = settings;
        _heuristicEnabled = settings?.Read().HeuristicEnabled ?? heuristicEnabled;
    }

    public bool HeuristicEnabled
    {
        get
        {
            lock (_lock)
            {
                return _heuristicEnabled;
            }
        }
    }

    public bool SetHeuristicEnabled(bool enabled)
    {
        lock (_lock)
        {
            _heuristicEnabled = enabled;
        }

        _settings?.Update(s => s.HeuristicEnabled = enabled);
        return enabled;
    }
}

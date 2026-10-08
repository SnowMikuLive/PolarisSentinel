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
        // A saved user choice wins over the configured default, so it survives a restart.
        _heuristicEnabled = settings?.Read().HeuristicEnabled ?? heuristicEnabled;
    }

    // True when the rule-based pre-filter/tracker gates flows before the AI engine. When
    // false, every flow is handed to the AI engine for a verdict.
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

    // Only a user action reaches this method, so it is the value to persist.
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

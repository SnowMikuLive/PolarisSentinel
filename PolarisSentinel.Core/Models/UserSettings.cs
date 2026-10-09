namespace PolarisSentinel.Core.Models;

// The operator's persisted choices. These follow the user across restarts and only
// change when the user changes them. A null value means "not chosen yet", so the
// configured default applies.
public class UserSettings
{
    public int Id { get; set; }

    public bool? DryRun { get; set; }

    public string? ModelCombination { get; set; }

    public string? CaptureDevice { get; set; }

    public bool? HeuristicEnabled { get; set; }
}

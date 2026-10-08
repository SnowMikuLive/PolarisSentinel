namespace PolarisSentinel.Core.Models;

// The operator's persisted choices. These follow the user across restarts and only
// change when the user changes them. A null value means "not chosen yet", so the
// configured default applies.
public class UserSettings
{
    // Primary key; the table always holds a single settings row.
    public int Id { get; set; }

    // Firewall enforcement: true = record-only (dry-run), false = write real blocks.
    public bool? DryRun { get; set; }

    // Active AI model combination, stored as a ModelCombination member name.
    public string? ModelCombination { get; set; }

    // Capture device the user selected (SharpPcap device name).
    public string? CaptureDevice { get; set; }

    // Heuristic (rule-based pre-filter/tracker) detection: true = filter then AI,
    // false = hand every flow straight to the AI engine.
    public bool? HeuristicEnabled { get; set; }
}

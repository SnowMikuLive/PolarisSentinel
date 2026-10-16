namespace PolarisSentinel.Core.Models;

public class UserSettings
{
    public int Id { get; set; }

    public bool? DryRun { get; set; }

    public string? ModelCombination { get; set; }

    public string? CaptureDevice { get; set; }

    public bool? HeuristicEnabled { get; set; }
}

using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// Per-user settings: detection thresholds.
// Defaults are seeded from appsettings on first use, then persisted per user.
public class UserSettings
{
    // ASP.NET Identity user id (owner of these settings); always assigned from the signed-in user.
    public string UserId { get; set; } = string.Empty;

    public float RfConfidenceThreshold { get; set; } = 0.6f;

    public float AutoBlockConfidenceThreshold { get; set; } = 0.8f;

    public double IfAnomalyThreshold { get; set; } = -0.150806;

    public int BlockDurationMinutes { get; set; } = 60;

    public int DecisionCooldownSeconds { get; set; } = 60;

    public int PreFilterMinPackets { get; set; } = 3;

    public int FlowIdleTimeoutMilliseconds { get; set; } = 120000;

    // Comma-separated CIDR entries; empty means none.
    public string Allowlist { get; set; } = string.Empty;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}

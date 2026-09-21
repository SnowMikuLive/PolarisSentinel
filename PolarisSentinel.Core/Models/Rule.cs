using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// A firewall rule created by the system or by hand.
// The firewall module owns persistence; this is the shared shape.
public class Rule
{
    // Human-readable id, e.g. "R-1".
    public string Id { get; set; } = string.Empty;

    // Windows Firewall rule name (e.g. "PolarisSentinel_Block_A-RF-1").
    public string Name { get; set; } = string.Empty;

    public string? PolicyId { get; set; }

    public Policy? Policy { get; set; }

    public string? AlertId { get; set; }

    public Alert? Alert { get; set; }

    public PolicyAction Action { get; set; }

    // 5-tuple the rule applies to.
    public string? SourceIp { get; set; } = string.Empty;

    public int? SourcePort { get; set; }

    public string? DestinationIp { get; set; } = string.Empty;

    public int? DestinationPort { get; set; }

    public byte? Protocol { get; set; }

    public bool Enabled { get; set; } = true;

    public string? AttackType { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.Now;

    public DateTime UpdatedAt { get; set; } = DateTime.Now;

    public DateTime? ExpiresAt { get; set; }
}

using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Constants;

namespace PolarisSentinel.Core.Models;

// A firewall rule. Can be created manually (no policy/alert) or derived
// from an alert under a policy (AI automation).
// Merged with the former FirewallRuleInfo summary type.
public class Rule
{
    // Human-readable id, e.g. "R-1".
    public string Id { get; set; } = string.Empty;

    // Firewall rule name (e.g. "PolarisSentinel_Block_...").
    public string Name { get; set; } = string.Empty;

    public string? PolicyId { get; set; }

    public Policy? Policy { get; set; }

    public string? AlertId { get; set; }

    public Alert? Alert { get; set; }

    public PolicyAction Action { get; set; }

    // Single IP or CIDR range (e.g. "203.0.113.10" or "203.0.113.0/24").
    public required string RemoteAddress { get; set; }

    // Whether the underlying firewall rule is enabled.
    public bool Enabled { get; set; } = true;

    public string? AttackType { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? ExpiresAt { get; set; }
}

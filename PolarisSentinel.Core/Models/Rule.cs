using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Constants;

namespace PolarisSentinel.Core.Models;

// A firewall rule. Can be created manually (no policy/alert) or derived
// from an alert under a policy (AI automation).
public class Rule
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid? PolicyId { get; set; }

    public Policy? Policy { get; set; }

    public Guid? AlertId { get; set; }

    public Alert? Alert { get; set; }

    public PolicyAction Action { get; set; }

    public required string RemoteAddress { get; set; }

    public RuleStatus Status { get; set; } = RuleStatus.Active;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? ExpiresAt { get; set; }
}

namespace PolarisSentinel.Core.Enums;

// Whether a firewall rule is currently in effect.
public enum RuleStatus
{
    // Rule is active and blocking/monitoring.
    Active,

    // Rule is disabled (exists but not applied).
    Inactive,

    // Rule has passed its expiry time.
    Expired
}

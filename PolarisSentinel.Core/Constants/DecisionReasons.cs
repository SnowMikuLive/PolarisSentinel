namespace PolarisSentinel.Core.Constants;

// Stable reason codes for a policy decision, plus human-readable descriptions.
// Modelled on Portmaster's connection "reason" concept: every verdict carries a
// machine code (for logic and filtering) and a plain-language explanation (for the UI),
// so the dashboard can always answer "why was this blocked or allowed?".
public static class DecisionReasons
{
    public const string Benign = "benign";

    public const string UnknownAnomaly = "unknown_anomaly";

    public const string SpoofedSource = "spoofed_source";

    public const string NoMatchingPolicy = "no_matching_policy";

    public const string PolicyAllow = "policy_allow";

    public const string PolicyMonitor = "policy_monitor";

    public const string PolicyBlock = "policy_block";

    public static string Describe(string reason) => reason switch
    {
        Benign => "Traffic classified as benign.",
        UnknownAnomaly => "Unnamed anomaly detected; monitored for a human decision.",
        SpoofedSource => "Source addresses were spoofed; no address block is possible, so this is monitored only.",
        NoMatchingPolicy => "No enabled policy matched this alert.",
        PolicyAllow => "Allowed by a matching policy.",
        PolicyMonitor => "Monitored by a matching policy (no block).",
        PolicyBlock => "Blocked by a matching policy.",
        _ => reason
    };
}

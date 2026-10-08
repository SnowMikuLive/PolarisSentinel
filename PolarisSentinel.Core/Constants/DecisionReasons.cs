namespace PolarisSentinel.Core.Constants;

// Stable reason codes for a policy decision, plus human-readable descriptions.
// Modelled on Portmaster's connection "reason" concept: every verdict carries a
// machine code (for logic and filtering) and a plain-language explanation (for the UI),
// so the dashboard can always answer "why was this blocked or allowed?".
public static class DecisionReasons
{
    // No action required: the flow was classified as benign.
    public const string Benign = "benign";

    // The Isolation Forest reported an unnamed anomaly; a human decides.
    public const string UnknownAnomaly = "unknown_anomaly";

    // No enabled policy matched the alert.
    public const string NoMatchingPolicy = "no_matching_policy";

    // A matching policy explicitly allowed the traffic.
    public const string PolicyAllow = "policy_allow";

    // A matching policy requested monitoring only.
    public const string PolicyMonitor = "policy_monitor";

    // A matching policy blocked the traffic and a firewall rule was applied.
    public const string PolicyBlock = "policy_block";

    // Plain-language text for each reason code.
    public static string Describe(string reason) => reason switch
    {
        Benign => "Traffic classified as benign.",
        UnknownAnomaly => "Unnamed anomaly detected; monitored for a human decision.",
        NoMatchingPolicy => "No enabled policy matched this alert.",
        PolicyAllow => "Allowed by a matching policy.",
        PolicyMonitor => "Monitored by a matching policy (no block).",
        PolicyBlock => "Blocked by a matching policy.",
        _ => reason
    };
}

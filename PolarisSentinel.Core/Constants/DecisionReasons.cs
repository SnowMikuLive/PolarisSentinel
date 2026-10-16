namespace PolarisSentinel.Core.Constants;

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

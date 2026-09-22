using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Constants;

// Human-readable ID prefixes and builders.
// Policy: P-1, Rule: R-1, Alert: A-RF-1 / A-IF-2 (global counter).
public static class EntityIds
{
    public const string PolicyPrefix = "P-";
    public const string RulePrefix = "R-";
    public const string AlertPrefix = "A-";

    // Windows Firewall rule name prefix, used to identify managed rules.
    public const string FirewallRulePrefix = "PolarisSentinel_";

    // Alert-id stand-in for a rule that constrains nothing and blocks all traffic.
    public const string AnyTrafficRuleName = "ANY";

    public static string Policy(int number) => $"{PolicyPrefix}{number}";

    public static string Rule(int number) => $"{RulePrefix}{number}";

    // Source tag: RandomForest -> RF, IsolationForest -> IF, PreFilter -> PF, otherwise RF.
    public static string Alert(DetectionSource source, int number)
    {
        string tag = source switch
        {
            DetectionSource.IsolationForest => "IF",
            DetectionSource.PreFilter => "PF",
            _ => "RF"
        };
        return $"{AlertPrefix}{tag}-{number}";
    }

    // Build a unique firewall rule name from an alert id.
    public static string FirewallRule(string alertId) => $"{FirewallRulePrefix}Block_{alertId}";
}

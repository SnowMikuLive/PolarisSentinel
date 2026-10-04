namespace PolarisSentinel.Core.Constants;

// Sequential P-/R-/A- id builders for policies, rules, and alerts.
public static class EntityIds
{
    public const string PolicyPrefix = "P-";
    public const string RulePrefix = "R-";
    public const string AlertPrefix = "A-";

    //托管防火墙规则名前缀
    //Prefix for managed Windows Firewall rule names
    public const string FirewallRulePrefix = "PolarisSentinel_";

    public static string Rule(int number) => $"{RulePrefix}{number}";

    // Sequential alert id, e.g. "A-1".
    public static string Alert(int number) => $"{AlertPrefix}{number}";

    // The highest numeric suffix among ids with the given prefix, or 0 when none exist.
    public static int MaxNumber(IEnumerable<string> ids, string prefix)
    {
        int max = 0;
        foreach (string id in ids)
        {
            if (id.StartsWith(prefix, StringComparison.Ordinal) &&
                int.TryParse(id.AsSpan(prefix.Length), out int n) && n > max)
            {
                max = n;
            }
        }
        return max;
    }

    //由告警主键生成唯一防火墙规则名
    //Build the managed firewall rule name from an alert id
    public static string FirewallRule(string alertId) => $"{FirewallRulePrefix}Block_{alertId}";
}

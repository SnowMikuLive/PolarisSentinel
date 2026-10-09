namespace PolarisSentinel.Core.Constants;

// Sequential P-/R-/A- id builders for policies, rules, and alerts.
public static class EntityIds
{
    public const string PolicyPrefix = "P-";
    public const string RulePrefix = "R-";
    public const string AlertPrefix = "A-";

    public const string FirewallRulePrefix = "PolarisSentinel_";

    public static string Rule(int number) => $"{RulePrefix}{number}";

    public static string Alert(int number) => $"{AlertPrefix}{number}";

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

    public static string Next(IEnumerable<string> ids, string prefix, Func<int, string> format) =>
        format(MaxNumber(ids, prefix) + 1);

    public static string FirewallRule(string targetKey) => $"{FirewallRulePrefix}Block_{targetKey}";
}

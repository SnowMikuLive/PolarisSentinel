namespace PolarisSentinel.Core.Constants;
// Sequential P-/R-/A- ids, reserved across concurrent application requests.
public static class EntityIds
{
    public const string PolicyPrefix = "P-";
    public const string RulePrefix = "R-";
    public const string AlertPrefix = "A-";

    public const string FirewallRulePrefix = "PolarisSentinel_";

    private static readonly object _idLock = new();
    private static readonly Dictionary<string, int> _lastReserved = new(StringComparer.Ordinal);

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
    public static int ReserveNextNumber(int storedMax, string prefix)
    {
        lock (_idLock)
        {
            int next = checked(Math.Max(storedMax, _lastReserved.GetValueOrDefault(prefix)) + 1);
            _lastReserved[prefix] = next;
            return next;
        }
    }

    public static string Next(IEnumerable<string> ids, string prefix, Func<int, string> format) =>
        format(ReserveNextNumber(MaxNumber(ids, prefix), prefix));

    public static string FirewallRule(string targetKey) => $"{FirewallRulePrefix}Block_{targetKey}";
}
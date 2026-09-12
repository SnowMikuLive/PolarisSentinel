namespace PolarisSentinel.Core.Constants;

public static class FirewallRuleNaming
{
    public const string Prefix = "PolarisSentinel_";

    // 由 AlertId 生成唯一规则名
    // Build a unique rule name from AlertId
    public static string BuildRuleName(Guid alertId) => $"{Prefix}Block_{alertId:N}";
}

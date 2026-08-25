namespace PolarisSentinel.Core.Constants;

public static class FirewallRuleNaming
{
    public const string Prefix = "PolarisSentinel_";

    //For generate uniqe rule id
    public static string BuildRuleName(Guid alertId) => $"{Prefix}Block_{alertId:N}";
}

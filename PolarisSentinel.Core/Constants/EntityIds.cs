using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Constants;

//保留旧P-/R-/A-编号；新告警与规则主键用NewId()。
//Keep legacy P-/R-/A- builders;new alert and rule rows use NewId().
public static class EntityIds
{
    //32字符GUID主键，避免重启、并发与删后重建时序号冲突。
    //32-char GUID keys avoid collisions across restarts,concurrency,and re-create.
    public static string NewId() => Guid.NewGuid().ToString("N");

    public const string PolicyPrefix = "P-";
    public const string RulePrefix = "R-";
    public const string AlertPrefix = "A-";

    //托管防火墙规则名前缀
    //Prefix for managed Windows Firewall rule names
    public const string FirewallRulePrefix = "PolarisSentinel_";

    //五元组全通配时的共享规则键（非单条告警ID）
    //Shared rule key when scope is unconstrained (not a single alert id)
    public const string AnyTrafficRuleName = "ANY";

    public static string Policy(int number) => $"{PolicyPrefix}{number}";

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

    //历史告警编号：RF/IF/PF来源标签+序号（仅旧数据/测试）
    //Legacy alert id:RF/IF/PF tag plus counter (old rows and tests only)
    public static string Alert(DetectionSource source, int number)
    {
        string tag = source switch
        {
            DetectionSource.IsolationForest => "IF",
            DetectionSource.HeuristicBased => "HB",
            _ => "RF"
        };
        return $"{AlertPrefix}{tag}-{number}";
    }

    //由告警主键生成唯一防火墙规则名
    //Build the managed firewall rule name from an alert id
    public static string FirewallRule(string alertId) => $"{FirewallRulePrefix}Block_{alertId}";
}

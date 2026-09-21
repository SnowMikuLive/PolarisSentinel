using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

//策略Block决策的防火墙执行接口
//Firewall execution contract for Block policy decisions
public interface IFirewallEnforcer
{
    // 按决策封禁，duration 指定规则有效期
    // Block from a decision for the supplied duration
    void BlockIp(Alert decision, TimeSpan duration);

    void RemoveRule(string ruleName);

    IEnumerable<Rule> GetAllRules();

    int RemoveExpiredRules();

    int RemoveAllManagedRules();
}

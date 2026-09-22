using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

//策略Block决策的防火墙执行接口
//Firewall execution contract for Block policy decisions
public interface IFirewallEnforcer
{
<<<<<<< HEAD
    //按决策封禁，duration指定规则有效期
    //Block from a decision for the supplied duration
    void BlockIp(Policy decision, TimeSpan duration);
=======
    // 按决策封禁，duration 指定规则有效期
    // Block from a decision for the supplied duration
    void BlockIp(Alert decision, TimeSpan duration);
>>>>>>> d47e7ec0c32803f010bc8a3c97a4dc42d392cd92

    void RemoveRule(string ruleName);

    IEnumerable<Rule> GetAllRules();

    int RemoveExpiredRules();

    int RemoveAllManagedRules();
}

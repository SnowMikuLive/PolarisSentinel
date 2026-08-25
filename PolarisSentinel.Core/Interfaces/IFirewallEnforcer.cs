using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IFirewallEnforcer
{
    void BlockIp(string ipAddress, Guid alertId);

    void RemoveRule(string ruleName);

    //Get all the rules
    IEnumerable<FirewallRuleInfo> GetAllRules();
}

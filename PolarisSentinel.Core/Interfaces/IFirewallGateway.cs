using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IFirewallGateway
{
    bool IsEnabled { get; }

    string? DisabledReason { get; }

    void Reevaluate();

    bool Apply(string ruleName, FirewallRuleSpec spec, bool ruleActive);

    void Remove(string ruleName);

    IReadOnlyList<string> ListManagedNames();

    IReadOnlyList<string> GetBlockedInboundAddresses();
}

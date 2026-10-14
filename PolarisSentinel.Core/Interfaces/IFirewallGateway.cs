using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Boundary to the Windows Firewall API. Registered as a singleton so the COM handle and the
// admin check are created once per process, and so enforcement can be tested without COM.
public interface IFirewallGateway
{
    bool IsEnabled { get; }

    string? DisabledReason { get; }

    void Reevaluate();

    bool Apply(string ruleName, FirewallRuleSpec spec, bool ruleActive);

    void Remove(string ruleName);

    IReadOnlyList<string> ListManagedNames();
}

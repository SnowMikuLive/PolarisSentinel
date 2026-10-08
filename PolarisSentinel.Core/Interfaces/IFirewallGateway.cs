using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Boundary to the Windows Firewall API. Registered as a singleton so the COM handle and the
// admin check are created once per process, and so enforcement can be tested without COM.
public interface IFirewallGateway
{
    // False when rules are only recorded (dry-run or no administrator rights).
    bool IsEnabled { get; }

    string? DisabledReason { get; }

    void Reevaluate();

    // Returns true when the rule was written to the operating system.
    bool Apply(string ruleName, FirewallRuleSpec spec, bool ruleActive);

    void Remove(string ruleName);

    IReadOnlyList<string> ListManagedNames();
}

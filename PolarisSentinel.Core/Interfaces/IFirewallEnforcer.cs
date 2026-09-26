using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Creates, updates and removes the Windows Firewall rules managed by Polaris Sentinel.
public interface IFirewallEnforcer
{
    // Applies a policy decision: creates the rule for the alert and stages it.
    // A null alertId marks a manual rule with no originating alert.
    Rule Apply(PolicyDecision decision, string? policyId, string? alertId, string? attackType, TimeSpan duration);

    // Update the scope / action / status of an existing rule.
    Rule? Update(
        string ruleId,
        string sourceIp,
        int sourcePort,
        string destinationIp,
        int destinationPort,
        byte protocol,
        PolicyAction action,
        RuleStatus status,
        TimeSpan duration);

    // Remove one rule by its id.
    bool Remove(string ruleId);

    // Remove every rule this application created.
    int RemoveAll();

    // Remove rules whose expiry has passed.
    int RemoveExpired();

    // Every rule this application created.
    IReadOnlyList<Rule> GetAllRules();

    Rule? GetById(string ruleId);
}

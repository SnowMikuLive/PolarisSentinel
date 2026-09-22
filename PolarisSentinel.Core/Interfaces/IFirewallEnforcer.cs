using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Firewall rule CRUD, driven by the 5-tuple plus a per-field scope.
public interface IFirewallEnforcer
{
    // Create a rule for the supplied scope. Null scope means the exact 5-tuple.
    // A null alertId marks a manual rule with no originating alert.
    // The rule is staged, not committed; the caller commits after the alert row exists.
    Rule Block(
        string sourceIp,
        int sourcePort,
        string destinationIp,
        int destinationPort,
        byte protocol,
        PolicyAction action,
        string? alertId,
        string? policyId,
        string? attackType,
        TimeSpan duration,
        FirewallRuleScope? scope = null);

    // Update the scope / action / enabled state of an existing rule.
    Rule? Update(
        string ruleId,
        string sourceIp,
        int sourcePort,
        string destinationIp,
        int destinationPort,
        byte protocol,
        PolicyAction action,
        bool enabled,
        TimeSpan duration,
        FirewallRuleScope? scope = null);

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

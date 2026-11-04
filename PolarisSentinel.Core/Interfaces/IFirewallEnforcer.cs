using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IFirewallEnforcer
{
    Rule Apply(PolicyDecision decision, string? policyId, string? alertId, string? attackType, TimeSpan duration,
        RuleStatus status = RuleStatus.Active);

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

    bool Remove(string ruleId);

    int RemoveAll();

    int RemoveExpired();

    int Reconcile();

    IReadOnlyList<Rule> GetAllRules();

    Rule? GetById(string ruleId);

    bool IsDryRun { get; }

    string? DryRunReason { get; }

    (bool DryRun, string? Reason) SetDryRun(bool dryRun);
}

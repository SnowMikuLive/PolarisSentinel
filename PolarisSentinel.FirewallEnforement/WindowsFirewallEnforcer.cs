using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.FirewallEnforement
{

    public class WindowsFirewallEnforcer : IFirewallEnforcer
    {
        private readonly IRuleRepository _rules;
        private readonly IFirewallGateway _gateway;
        private readonly FirewallRuntimeState _state;
        private readonly TimeProvider _timeProvider;
        private readonly ILogger<WindowsFirewallEnforcer> _logger;

        private static readonly object _lock = new object();

        public bool IsDryRun => !_gateway.IsEnabled;

        public string? DryRunReason => _gateway.DisabledReason;

        public WindowsFirewallEnforcer(
            IRuleRepository rules,
            IFirewallGateway gateway,
            FirewallRuntimeState state,
            TimeProvider timeProvider,
            ILogger<WindowsFirewallEnforcer> logger)
        {
            _rules = rules;
            _gateway = gateway;
            _state = state;
            _timeProvider = timeProvider;
            _logger = logger;
        }

        public (bool DryRun, string? Reason) SetDryRun(bool dryRun)
        {
            _state.DryRun = dryRun;
            _gateway.Reevaluate();
            return (IsDryRun, DryRunReason);
        }

        private const int MaxActiveAddressRules = 500;

        private static string BuildRuleName(PolicyAction action, FirewallRuleSpec spec)
        {
            string target = spec.RemoteAddress ?? spec.LocalPort?.ToString() ?? spec.RemotePort?.ToString() ?? string.Empty;

            return spec.RemoteAddress is not null
                ? EntityIds.FirewallRule($"{action}_{target}")
                : EntityIds.FirewallRule($"{action}_{target}_{spec.Protocol}");
        }

        public Rule Apply(PolicyDecision decision, string? policyId, string? alertId, string? attackType, TimeSpan duration)
        {
            var alert = decision.Alert;
            var spec = FirewallRuleSpec.TryCreate(decision.Action, alert, out string? error);
            if (spec == null)
            {
                throw new InvalidOperationException(error ?? "The policy action cannot be applied to this alert.");
            }

            lock (_lock)
            {
                var now = _timeProvider.GetLocalNow().DateTime;
                var expiresAt = now.Add(duration);

                string ruleName = BuildRuleName(decision.Action, spec);

                var existing = _rules.GetByNameAsync(ruleName).GetAwaiter().GetResult();
                if (existing != null)
                {
                    if (expiresAt > existing.ExpiresAt)
                    {
                        existing.ExpiresAt = expiresAt;
                        existing.UpdatedAt = now;
                        existing.Status = RuleStatus.Active;
                        _rules.Update(existing);
                        _rules.SaveChangesAsync().GetAwaiter().GetResult();
                    }

                    if (existing.Status == RuleStatus.Active)
                    {
                        SaveToWindows(existing, SpecFrom(existing));
                    }
                    return existing;
                }

                int activeAddressRules = _rules.GetAllAsync().GetAwaiter().GetResult()
                    .Count(r => r.Status == RuleStatus.Active && r.BlocksAddress);

                if (activeAddressRules >= MaxActiveAddressRules)
                {
                    _logger.LogWarning(
                        "Refusing to create a firewall rule for {Action}: the active address-block limit ({Limit}) is reached",
                        decision.Action, MaxActiveAddressRules);
                    throw new InvalidOperationException(
                        $"The active address-block limit ({MaxActiveAddressRules}) is reached, so no new firewall rule was created.");
                }

                var rule = new Rule
                {
                    Id = _rules.NextIdAsync().GetAwaiter().GetResult(),
                    Name = ruleName,
                    PolicyId = string.IsNullOrEmpty(policyId) ? null : policyId,
                    AlertId = string.IsNullOrEmpty(alertId) ? null : alertId,
                    Action = decision.Action,
                    Status = RuleStatus.Active,
                    SourceIp = alert.SourceIp,
                    SourcePort = alert.SourcePort == 0 ? null : alert.SourcePort,
                    DestinationIp = alert.DestinationIp,
                    DestinationPort = alert.DestinationPort == 0 ? null : alert.DestinationPort,
                    Protocol = spec.Protocol,
                    CreatedAt = now,
                    UpdatedAt = now,
                    ExpiresAt = expiresAt
                };

                _rules.Add(rule);
                _rules.SaveChangesAsync().GetAwaiter().GetResult();
                SaveToWindows(rule, spec);
                if (_logger.IsEnabled(LogLevel.Information))
                {
                    _logger.LogInformation("Firewall applied {RuleName} for {Action}, expires {ExpiresAt}, dry-run {DryRun}",
                        ruleName, decision.Action, expiresAt, IsDryRun);
                }
                return rule;
            }
        }

        public Rule? Update(
            string ruleId,
            string sourceIp,
            int sourcePort,
            string destinationIp,
            int destinationPort,
            byte protocol,
            PolicyAction action,
            RuleStatus status,
            TimeSpan duration)
        {
            lock (_lock)
            {
                var rule = _rules.GetByIdAsync(ruleId).GetAwaiter().GetResult();
                if (rule == null)
                {
                    return null;
                }

                var now = _timeProvider.GetLocalNow().DateTime;
                RemoveFromWindows(rule.Name);

                rule.Action = action;
                rule.Status = status;
                rule.SourceIp = sourceIp ?? string.Empty;
                rule.SourcePort = sourcePort == 0 ? null : sourcePort;
                rule.DestinationIp = destinationIp ?? string.Empty;
                rule.DestinationPort = destinationPort == 0 ? null : destinationPort;
                rule.Protocol = protocol;
                rule.ExpiresAt = now.Add(duration);
                rule.UpdatedAt = now;

                var updatedSpec = SpecFrom(rule);
                if (updatedSpec is not null)
                {
                    rule.Name = BuildRuleName(rule.Action, updatedSpec);
                }

                _rules.Update(rule);
                _rules.SaveChangesAsync().GetAwaiter().GetResult();
                if (status == RuleStatus.Active)
                {
                    SaveToWindows(rule, SpecFrom(rule));
                }
                if (_logger.IsEnabled(LogLevel.Information))
                {
                    _logger.LogInformation("Firewall updated {RuleName}", rule.Name);
                }
                return rule;
            }
        }

        public bool Remove(string ruleId)
        {
            lock (_lock)
            {
                var rule = _rules.GetByIdAsync(ruleId).GetAwaiter().GetResult();
                if (rule == null)
                {
                    return false;
                }

                RemoveFromWindows(rule.Name);
                _rules.Remove(rule);
                _rules.SaveChangesAsync().GetAwaiter().GetResult();
                if (_logger.IsEnabled(LogLevel.Information))
                {
                    _logger.LogInformation("Firewall removed {RuleName}", rule.Name);
                }
                return true;
            }
        }

        public int RemoveAll()
        {
            lock (_lock)
            {
                var all = _rules.GetAllAsync().GetAwaiter().GetResult();
                foreach (var rule in all)
                {
                    RemoveFromWindows(rule.Name);
                    _rules.Remove(rule);
                }
                _rules.SaveChangesAsync().GetAwaiter().GetResult();
                if (_logger.IsEnabled(LogLevel.Information))
                {
                    _logger.LogInformation("Removed {Count} managed firewall rule(s)", all.Count);
                }
                return all.Count;
            }
        }

        public int RemoveExpired()
        {
            lock (_lock)
            {
                var now = _timeProvider.GetLocalNow().DateTime;
                var expired = _rules.GetAllAsync().GetAwaiter().GetResult()
                    .Where(r => r.Status == RuleStatus.Active && r.ExpiresAt != null && r.ExpiresAt <= now)
                    .ToList();

                int removed = 0;
                foreach (var rule in expired)
                {
                    if (TryExpireRule(rule, now))
                    {
                        removed++;
                    }
                }
                if (removed > 0)
                {
                    _rules.SaveChangesAsync().GetAwaiter().GetResult();
                    if (_logger.IsEnabled(LogLevel.Information))
                    {
                        _logger.LogInformation("Expired {Count} firewall rule(s)", removed);
                    }
                }
                return removed;
            }
        }

        private bool TryExpireRule(Rule rule, DateTime now)
        {
            try
            {
                RemoveFromWindows(rule.Name);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to remove expired firewall rule {RuleName}; will retry", rule.Name);
                return false;
            }

            rule.Status = RuleStatus.Expired;
            rule.UpdatedAt = now;
            _rules.Update(rule);
            return true;
        }

        public int Reconcile()
        {
            lock (_lock)
            {
                var managed = _gateway.ListManagedNames();
                if (managed.Count == 0 && !_gateway.IsEnabled)
                {
                    return 0;
                }

                var managedSet = managed.ToHashSet(StringComparer.Ordinal);
                var rules = _rules.GetAllAsync().GetAwaiter().GetResult();
                var tracked = rules
                    .Where(r => r.Status == RuleStatus.Active)
                    .Select(r => r.Name)
                    .Where(n => !string.IsNullOrEmpty(n))
                    .ToHashSet(StringComparer.Ordinal);

                int changes = 0;

                foreach (var name in managedSet)
                {
                    if (tracked.Contains(name))
                    {
                        continue;
                    }

                    try
                    {
                        _gateway.Remove(name);
                        changes++;
                        if (_logger.IsEnabled(LogLevel.Information))
                        {
                            _logger.LogInformation("Removed untracked or inactive firewall rule {RuleName}", name);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to remove orphaned firewall rule {RuleName}", name);
                    }
                }

                foreach (var rule in rules)
                {
                    if (rule.Status != RuleStatus.Active ||
                        string.IsNullOrEmpty(rule.Name) ||
                        managedSet.Contains(rule.Name))
                    {
                        continue;
                    }

                    var spec = FirewallRuleSpec.FromRule(rule);
                    if (spec is null)
                    {
                        _logger.LogWarning("Cannot re-push rule {RuleName}: its action is not representable", rule.Name);
                        continue;
                    }

                    try
                    {
                        if (_gateway.Apply(rule.Name, spec, ruleActive: true))
                        {
                            changes++;
                            if (_logger.IsEnabled(LogLevel.Information))
                            {
                                _logger.LogInformation("Re-pushed missing firewall rule {RuleName}", rule.Name);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to re-push firewall rule {RuleName}", rule.Name);
                    }
                }

                if (changes > 0)
                {
                    _logger.LogWarning("Reconciled firewall: {Count} change(s)", changes);
                }
                return changes;
            }
        }

        public IReadOnlyList<Rule> GetAllRules()
        {
            lock (_lock)
            {
                return _rules.GetAllAsync().GetAwaiter().GetResult();
            }
        }

        public Rule? GetById(string ruleId)
        {
            lock (_lock)
            {
                return _rules.GetByIdAsync(ruleId).GetAwaiter().GetResult();
            }
        }

        private static FirewallRuleSpec? SpecFrom(Rule rule) => FirewallRuleSpec.FromRule(rule);

        private void SaveToWindows(Rule rule, FirewallRuleSpec? spec)
        {
            if (spec is null)
            {
                _logger.LogWarning("Cannot apply rule {RuleName}: its action is not representable", rule.Name);
                return;
            }

            _gateway.Apply(rule.Name, spec, rule.Status == RuleStatus.Active);
        }

        private void RemoveFromWindows(string ruleName)
        {
            if (!string.IsNullOrEmpty(ruleName))
            {
                _gateway.Remove(ruleName);
            }
        }
    }
}

using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.FirewallEnforement
{
    // Applies firewall rules to Windows Firewall and mirrors them into the rule repository.
    // DryRun skips new Windows blocks; existing rules are still removed when requested or expired.
    public class WindowsFirewallEnforcer : IFirewallEnforcer
    {
        private readonly IRuleRepository _rules;
        private readonly FirewallRuntimeState _state;
        private WindowsFirewall? _firewall;
        private readonly TimeProvider _timeProvider;
        private readonly ILogger<WindowsFirewallEnforcer> _logger;

        // Process-wide: every DI scope builds its own enforcer (one per processed flow),
        // and the sweeper and manual rule management run on other threads. Rule ids are
        // allocated by scanning the table, so rule mutations must be serialized across all
        // instances or concurrent blocks can collide on the same id.
        private static readonly object _lock = new object();

        public bool IsDryRun => _firewall == null;

        public string? DryRunReason { get; private set; }

        public WindowsFirewallEnforcer(
            IRuleRepository rules,
            IOptions<FirewallOptions> options,
            FirewallRuntimeState state,
            TimeProvider timeProvider,
            ILogger<WindowsFirewallEnforcer> logger)
        {
            _rules = rules;
            _state = state;
            _timeProvider = timeProvider;
            _logger = logger;

            // The runtime state (seeded from config) is the source of truth; it can be
            // toggled from the dashboard after startup.
            EvaluateEnforcement();
        }

        // Opens or releases the real Windows Firewall handle to match the runtime DryRun flag.
        // Called at construction and whenever the dashboard toggles the setting.
        private void EvaluateEnforcement()
        {
            lock (_lock)
            {
                if (_state.DryRun)
                {
                    _firewall = null;
                    DryRunReason = "disabled (dry-run enabled from the dashboard)";
                    _logger.LogWarning("Firewall DRY-RUN: {Reason}. Detections are recorded but NOT blocked.", DryRunReason);
                    return;
                }

                try
                {
                    if (!OperatingSystem.IsWindows())
                    {
                        _firewall = null;
                        DryRunReason = "Windows Firewall is unavailable on this platform";
                        _logger.LogError("Firewall DRY-RUN: {Reason}. Detections are recorded but NOT blocked.", DryRunReason);
                        return;
                    }

                    using var identity = WindowsIdentity.GetCurrent();
                    var principal = new WindowsPrincipal(identity);
                    // Writing the system firewall needs administrator rights.
                    if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                    {
                        _firewall = null;
                        DryRunReason = "administrator rights are required";
                        _logger.LogError("Firewall DRY-RUN: {Reason}. Detections are recorded but NOT blocked.", DryRunReason);
                        return;
                    }

                    _firewall = new WindowsFirewall();
                    DryRunReason = null;
                    _logger.LogInformation("Real Windows Firewall execution enabled");
                }
                catch (Exception ex)
                {
                    _firewall = null;
                    DryRunReason = "Windows Firewall could not be opened";
                    _logger.LogError(ex, "Firewall DRY-RUN: {Reason}. Detections are recorded but NOT blocked.", DryRunReason);
                }
            }
        }

        // Turns dry-run on/off at runtime and returns the resulting enforcement status.
        public (bool DryRun, string? Reason) SetDryRun(bool dryRun)
        {
            _state.DryRun = dryRun;
            EvaluateEnforcement();
            return (IsDryRun, DryRunReason);
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
                var ruleId = _rules.NextIdAsync().GetAwaiter().GetResult();

                // Name the rule after the block target, not the alert, so repeated attacks
                // from the same source reuse and extend one rule instead of piling up.
                string target = spec.RemoteAddress ?? spec.LocalPort?.ToString() ?? spec.RemotePort?.ToString() ?? string.Empty;
                string ruleName = EntityIds.FirewallRule($"{decision.Action}_{target}_{spec.Protocol}");

                var existing = _rules.GetAllAsync().GetAwaiter().GetResult()
                    .FirstOrDefault(r => r.Name == ruleName);
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

                    // Re-push an active rule so it is enforced even if it was first recorded
                    // while dry-run was on or its Windows entry was otherwise lost. A
                    // non-active rule is left disabled (operator intent).
                    if (existing.Status == RuleStatus.Active)
                    {
                        SaveToWindows(existing, SpecFrom(existing));
                    }
                    return existing;
                }

                // The rule's 5-tuple mirrors the originating alert. What is blocked is
                // derived from the action (see Rule.BlockedIp / Rule.BlockedPort).
                var rule = new Rule
                {
                    Id = ruleId,
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
                _logger.LogInformation("Firewall applied {RuleName} for {Action}, expires {ExpiresAt}, dry-run {DryRun}",
                    ruleName, decision.Action, expiresAt, IsDryRun);
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

                _rules.Update(rule);
                _rules.SaveChangesAsync().GetAwaiter().GetResult();
                if (status == RuleStatus.Active)
                {
                    SaveToWindows(rule, SpecFrom(rule));
                }
                _logger.LogInformation("Firewall updated {RuleName}", rule.Name);
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
                _logger.LogInformation("Firewall removed {RuleName}", rule.Name);
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
                _logger.LogInformation("Removed {Count} managed firewall rule(s)", all.Count);
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
                    try
                    {
                        RemoveFromWindows(rule.Name);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to remove expired firewall rule {RuleName}; will retry", rule.Name);
                        continue;
                    }
                    rule.Status = RuleStatus.Expired;
                    rule.UpdatedAt = now;
                    _rules.Update(rule);
                    removed++;
                }
                if (removed > 0)
                {
                    _rules.SaveChangesAsync().GetAwaiter().GetResult();
                    _logger.LogInformation("Expired {Count} firewall rule(s)", removed);
                }
                return removed;
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

        private static FirewallRuleSpec SpecFrom(Rule rule) => FirewallRuleSpec.FromRule(rule);

        // Push a rule to the Windows Firewall API (skipped in dry-run).
        private void SaveToWindows(Rule rule, FirewallRuleSpec spec)
        {
            if (_firewall == null || !OperatingSystem.IsWindows())
            {
                return;
            }

            // An address rule normalises the remote address; a port rule leaves it as
            // "*" (any) and scopes the block with the local/remote port instead.
            bool anyAddress = string.IsNullOrWhiteSpace(spec.RemoteAddress);
            string? ip = anyAddress ? "*" : NormalizeIp(spec.RemoteAddress!);
            if (ip == null)
            {
                _logger.LogWarning("Cannot apply rule {RuleName}: invalid address {Address}", rule.Name, spec.RemoteAddress);
                return;
            }

            _firewall.Save(new FirewallStoredRule
            {
                Name = rule.Name,
                RemoteAddress = ip,
                LocalPort = spec.LocalPort ?? 0,
                RemotePort = spec.RemotePort ?? 0,
                Protocol = spec.Protocol,
                Enabled = rule.Status == RuleStatus.Active,
                Direction = spec.Direction
            });
        }

        private void RemoveFromWindows(string ruleName)
        {
            if (!string.IsNullOrEmpty(ruleName))
            {
                RemoveWindowsRule(ruleName);
            }
        }

        // Cleanup must work in dry-run without enabling new blocks.
        protected virtual void RemoveWindowsRule(string ruleName)
        {
            if (!OperatingSystem.IsWindows()) return;
            var cleanupFirewall = _firewall ?? new WindowsFirewall();
            cleanupFirewall.Remove(ruleName);
        }

        private static string? NormalizeIp(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            return NetworkAddress.TryNormalize(value, out var normalized) ? normalized : null;
        }
    }
}

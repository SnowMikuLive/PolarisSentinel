using System.Net;
using System.Net.Sockets;
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
    // DryRun keeps the Windows side untouched; the repository is always written.
    public class WindowsFirewallEnforcer : IFirewallEnforcer
    {
        private readonly IRuleRepository _rules;
        private readonly WindowsFirewall? _firewall;
        private readonly TimeProvider _timeProvider;
        private readonly ILogger<WindowsFirewallEnforcer> _logger;
        private readonly object _lock = new object();

        public bool IsDryRun => _firewall == null;

        public WindowsFirewallEnforcer(
            IRuleRepository rules,
            IOptions<FirewallOptions> options,
            TimeProvider timeProvider,
            ILogger<WindowsFirewallEnforcer> logger)
        {
            _rules = rules;
            _timeProvider = timeProvider;
            _logger = logger;

            if (options.Value.DryRun)
            {
                _logger.LogInformation("Firewall dry-run enabled");
                return;
            }

            try
            {
                if (!OperatingSystem.IsWindows())
                {
                    _logger.LogError("Windows Firewall is unavailable; using dry-run");
                    return;
                }
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                // Writing the system firewall needs administrator rights.
                if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    _logger.LogError("Administrator rights are required; using dry-run");
                    return;
                }
                _firewall = new WindowsFirewall();
                _logger.LogInformation("Real Windows Firewall execution enabled");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Cannot open Windows Firewall; using dry-run");
            }
        }

        // Create a rule for the scope, or extend the expiry of an equivalent existing one.
        public Rule Block(
            string sourceIp,
            int sourcePort,
            string destinationIp,
            int destinationPort,
            byte protocol,
            PolicyAction action,
            string? alertId,
            string? attackType,
            TimeSpan duration,
            FirewallRuleScope? scope = null)
        {
            if (duration <= TimeSpan.Zero)
            {
                _logger.LogWarning("Invalid block request for {Ip}", sourceIp);
                return new Rule { Id = string.Empty, Name = string.Empty, SourceIp = sourceIp };
            }

            // Without an explicit scope the exact 5-tuple is used.
            scope ??= new FirewallRuleScope
            {
                SourceIp = sourceIp ?? string.Empty,
                SourcePort = sourcePort,
                DestinationIp = destinationIp ?? string.Empty,
                DestinationPort = destinationPort,
                Protocol = protocol
            };

            lock (_lock)
            {
                var now = _timeProvider.GetLocalNow().DateTime;
                var expiresAt = now.Add(duration);
                var ruleId = EntityIds.Rule(NextRuleNumber());

                // A rule that constrains nothing blocks every flow, so it must not be
                // tied to a single alert id; one shared rule is reused instead.
                // Manual rules have no alert at all, so they key off their own id.
                string ruleName = scope.IsAny
                    ? EntityIds.FirewallRule(EntityIds.AnyTrafficRuleName)
                    : EntityIds.FirewallRule(string.IsNullOrEmpty(alertId) ? ruleId : alertId);

                var existing = _rules.GetAllAsync().GetAwaiter().GetResult()
                    .FirstOrDefault(r => r.Name == ruleName);

                if (existing != null)
                {
                    // Same rule already present: only push the expiry out.
                    if (expiresAt > existing.ExpiresAt)
                    {
                        existing.ExpiresAt = expiresAt;
                        existing.UpdatedAt = now;
                        _rules.Update(existing);
                        _rules.SaveChangesAsync().GetAwaiter().GetResult();
                        SaveToWindows(existing);
                        _logger.LogInformation("Firewall extended for {RuleName}, expires {ExpiresAt}", ruleName, expiresAt);
                    }
                    return existing;
                }

                var rule = new Rule
                {
                    Id = ruleId,
                    Name = ruleName,
                    PolicyId = null,
                    // Null for manual rules: AlertId is a foreign key, so a synthetic
                    // value that is not in the Alerts table would violate it.
                    AlertId = string.IsNullOrEmpty(alertId) ? null : alertId,
                    Action = action,
                    Enabled = true,
                    AttackType = attackType,
                    CreatedAt = now,
                    ExpiresAt = expiresAt
                };
                // Any field left empty/zero is a wildcard, not a constraint.
                scope.ApplyTo(rule);

                _rules.Add(rule);
                _rules.SaveChangesAsync().GetAwaiter().GetResult();
                SaveToWindows(rule);
                _logger.LogInformation("Firewall created {RuleName} for {SourceIp}, expires {ExpiresAt}, dry-run {DryRun}",
                    ruleName, sourceIp, expiresAt, IsDryRun);
                return rule;
            }
        }

        // Update an existing rule's scope, action, enabled state and expiry.
        public Rule? Update(
            string ruleId,
            string sourceIp,
            int sourcePort,
            string destinationIp,
            int destinationPort,
            byte protocol,
            PolicyAction action,
            bool enabled,
            TimeSpan duration,
            FirewallRuleScope? scope = null)
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

                scope ??= new FirewallRuleScope
                {
                    SourceIp = sourceIp ?? string.Empty,
                    SourcePort = sourcePort,
                    DestinationIp = destinationIp ?? string.Empty,
                    DestinationPort = destinationPort,
                    Protocol = protocol
                };
                scope.ApplyTo(rule);
                rule.Action = action;
                rule.Enabled = enabled;
                rule.ExpiresAt = now.Add(duration);
                rule.UpdatedAt = now;

                _rules.Update(rule);
                _rules.SaveChangesAsync().GetAwaiter().GetResult();
                SaveToWindows(rule);
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
                    .Where(r => r.ExpiresAt != null && r.ExpiresAt <= now)
                    .ToList();

                foreach (var rule in expired)
                {
                    RemoveFromWindows(rule.Name);
                    _rules.Remove(rule);
                }
                if (expired.Count > 0)
                {
                    _rules.SaveChangesAsync().GetAwaiter().GetResult();
                    _logger.LogInformation("Removed {Count} expired firewall rule(s)", expired.Count);
                }
                return expired.Count;
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

        // Push a rule to the Windows Firewall API (skipped in dry-run).
        private void SaveToWindows(Rule rule)
        {
            if (_firewall == null || !OperatingSystem.IsWindows())
            {
                return;
            }

            // Empty address means Any: Windows Firewall uses "*" for that.
            bool anyAddress = string.IsNullOrWhiteSpace(rule.SourceIp);
            string? ip = anyAddress ? "*" : NormalizeIp(rule.SourceIp);
            if (ip == null)
            {
                _logger.LogWarning("Cannot apply rule {RuleName}: invalid source address {SourceIp}", rule.Name, rule.SourceIp);
                return;
            }

            // Port 0 and protocol 0 mean Any and are passed through as wildcards.
            _firewall.Save(new FirewallStoredRule
            {
                Name = rule.Name,
                RemoteAddress = ip,
                LocalPort = Math.Max(0, rule.DestinationPort),
                RemotePort = Math.Max(0, rule.SourcePort),
                Protocol = rule.Protocol,
                Enabled = rule.Enabled,
                IsBlockRule = rule.Action == PolicyAction.Block,
                Direction = 1
            });
        }

        private void RemoveFromWindows(string ruleName)
        {
            if (_firewall != null && OperatingSystem.IsWindows() && !string.IsNullOrEmpty(ruleName))
            {
                _firewall.Remove(ruleName);
            }
        }

        // Next "R-n" id, scanned from the stored rules.
        private int NextRuleNumber()
        {
            int max = 0;
            foreach (var rule in _rules.GetAllAsync().GetAwaiter().GetResult())
            {
                if (rule.Id.StartsWith(EntityIds.RulePrefix, StringComparison.Ordinal) &&
                    int.TryParse(rule.Id.AsSpan(EntityIds.RulePrefix.Length), out int n) && n > max)
                {
                    max = n;
                }
            }
            return max + 1;
        }

        private static string? NormalizeIp(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }
            if (!IPAddress.TryParse(value.Split('/')[0], out var address))
            {
                return null;
            }
            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }
            return address.ToString();
        }
    }
}

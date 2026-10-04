using System.Net;
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
                string ruleName = EntityIds.FirewallRule(string.IsNullOrEmpty(alertId) ? ruleId : alertId);

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
                        SaveToWindows(existing, SpecFrom(existing));
                    }
                    return existing;
                }

                var rule = new Rule
                {
                    Id = ruleId,
                    Name = ruleName,
                    PolicyId = string.IsNullOrEmpty(policyId) ? null : policyId,
                    AlertId = string.IsNullOrEmpty(alertId) ? null : alertId,
                    Action = decision.Action,
                    Status = RuleStatus.Active,
                    SourceIp = spec.Direction == 1 ? spec.RemoteAddress ?? string.Empty : string.Empty,
                    SourcePort = null,
                    DestinationIp = spec.Direction == 2 ? spec.RemoteAddress ?? string.Empty : string.Empty,
                    DestinationPort = spec.LocalPort ?? spec.RemotePort,
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

                foreach (var rule in expired)
                {
                    RemoveFromWindows(rule.Name);
                    rule.Status = RuleStatus.Expired;
                    rule.UpdatedAt = now;
                    _rules.Update(rule);
                }
                if (expired.Count > 0)
                {
                    _rules.SaveChangesAsync().GetAwaiter().GetResult();
                    _logger.LogInformation("Expired {Count} firewall rule(s)", expired.Count);
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

        private static FirewallRuleSpec SpecFrom(Rule rule) => new()
        {
            Direction = rule.Action is PolicyAction.BlockOutboundIp or PolicyAction.BlockOutboundPort ? 2 : 1,
            RemoteAddress = rule.Action == PolicyAction.BlockInboundIp ? rule.SourceIp :
                rule.Action == PolicyAction.BlockOutboundIp ? rule.DestinationIp : null,
            LocalPort = rule.Action == PolicyAction.BlockInboundPort ? rule.DestinationPort : null,
            RemotePort = rule.Action == PolicyAction.BlockOutboundPort ? rule.DestinationPort : null,
            Protocol = rule.Protocol ?? 0
        };

        // Push a rule to the Windows Firewall API (skipped in dry-run).
        private void SaveToWindows(Rule rule, FirewallRuleSpec spec)
        {
            if (_firewall == null || !OperatingSystem.IsWindows())
            {
                return;
            }

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
                IsBlockRule = true,
                Direction = spec.Direction
            });
        }

        private void RemoveFromWindows(string ruleName)
        {
            if (_firewall != null && OperatingSystem.IsWindows() && !string.IsNullOrEmpty(ruleName))
            {
                _firewall.Remove(ruleName);
            }
        }

        private static string? NormalizeIp(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            // Keep the CIDR prefix so a subnet block reaches Windows Firewall intact.
            var segments = value.Split('/');
            if (segments.Length > 2 || !IPAddress.TryParse(segments[0], out var address))
            {
                return null;
            }

            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }

            if (segments.Length == 2)
            {
                if (!int.TryParse(segments[1], out int prefix) || prefix < 0 || prefix > 128)
                {
                    return null;
                }
                return $"{address}/{prefix}";
            }

            return address.ToString();
        }
    }
}

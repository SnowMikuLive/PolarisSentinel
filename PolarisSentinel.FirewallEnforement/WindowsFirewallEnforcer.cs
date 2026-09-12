using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.FirewallEnforement
{
    // Windows 防火墙执行器；DryRun 时仅维护内存规则
    // Windows firewall enforcer; DryRun keeps rules in memory only
    public class WindowsFirewallEnforcer : IFirewallEnforcer
    {
        private readonly Dictionary<string, FirewallStoredRule> _rules = new Dictionary<string, FirewallStoredRule>();
        private readonly WindowsFirewall? _firewall;
        private readonly TimeProvider _timeProvider;
        private readonly ILogger<WindowsFirewallEnforcer> _logger;
        private readonly object _lock = new object();
        private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        public bool IsDryRun { get { return _firewall == null; } }

        public WindowsFirewallEnforcer(IOptions<FirewallOptions> options, TimeProvider timeProvider,
            ILogger<WindowsFirewallEnforcer> logger)
        {
            _timeProvider = timeProvider;
            _logger = logger;
            // 默认只使用内存规则
            // Use in-memory rules by default
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

        public void BlockIp(PolicyDecision decision, TimeSpan duration)
        {
            if (decision == null || decision.Action != PolicyAction.Block)
            {
                return;
            }
            string? ip = NormalizeIp(decision.SourceIp);
            if (ip == null || duration <= TimeSpan.Zero || decision.AlertId == Guid.Empty ||
                !float.IsFinite(decision.Confidence) || decision.Confidence < 0 || decision.Confidence > 1)
            {
                _logger.LogWarning("Invalid block request for {Ip}", decision.SourceIp);
                return;
            }

            lock (_lock)
            {
                try
                {
                    var now = _timeProvider.GetUtcNow();
                    var expiresAt = now.Add(duration);
                    var metadata = new FirewallRuleMetadata
                    {
                        AlertId = decision.AlertId,
                        Ip = ip,
                        AttackType = decision.AttackType,
                        Confidence = decision.Confidence,
                        CreatedAt = now
                    };
                    var rule = new FirewallStoredRule { Name = FirewallRuleNaming.BuildRuleName(decision.AlertId) };

                    // 同一 IP 复用原规则，只延长有效期
                    // Reuse the existing rule for the same IP; extend expiry only
                    foreach (var existingRule in GetRules())
                    {
                        var existing = ReadMetadata(existingRule);
                        if (existing == null || !existingRule.Enabled || !existingRule.IsBlockRule ||
                            existingRule.Direction != 1 || NormalizeIp(existing.Ip) != ip || existing.ExpiresAt <= now)
                        {
                            continue;
                        }
                        if (expiresAt <= existing.ExpiresAt)
                        {
                            return;
                        }
                        rule = existingRule;
                        metadata = existing;
                        break;
                    }

                    metadata.ExpiresAt = expiresAt;
                    rule.RemoteAddress = ip;
                    // Description 字段不接受竖线
                    // Description field does not accept a literal pipe
                    rule.Description = JsonSerializer.Serialize(metadata, JsonOptions).Replace("|", "\\u007C");
                    if (_firewall != null && OperatingSystem.IsWindows())
                    {
                        _firewall.Save(rule);
                    }
                    else
                    {
                        _rules[rule.Name] = rule;
                    }
                    _logger.LogInformation("Saved block for {Ip}, alert {AlertId}, expires {ExpiresAt}, dry-run {DryRun}",
                        ip, metadata.AlertId, expiresAt, IsDryRun);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Cannot block {Ip}", ip);
                }
            }
        }

        public IEnumerable<FirewallRuleInfo> GetAllRules()
        {
            var result = new List<FirewallRuleInfo>();
            lock (_lock)
            {
                try
                {
                    foreach (var rule in GetRules())
                    {
                        var metadata = ReadMetadata(rule);
                        result.Add(new FirewallRuleInfo
                        {
                            Name = rule.Name,
                            RemoteAddress = rule.RemoteAddress,
                            Enabled = rule.Enabled,
                            IsBlockRule = rule.IsBlockRule,
                            AlertId = metadata?.AlertId,
                            CreatedAt = metadata?.CreatedAt,
                            ExpiresAt = metadata?.ExpiresAt,
                            AttackType = metadata?.AttackType
                        });
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Cannot list firewall rules");
                }
            }
            return result;
        }

        public void RemoveRule(string ruleName)
        {
            if (!string.IsNullOrEmpty(ruleName) && ruleName.StartsWith(FirewallRuleNaming.Prefix, StringComparison.Ordinal))
            {
                RemoveRules(ruleName, false);
            }
        }

        public int RemoveExpiredRules()
        {
            return RemoveRules(null, true);
        }

        public int RemoveAllManagedRules()
        {
            return RemoveRules(null, false);
        }

        private int RemoveRules(string? ruleName, bool expiredOnly)
        {
            int removed = 0;
            lock (_lock)
            {
                try
                {
                    var now = _timeProvider.GetUtcNow();
                    foreach (var rule in GetRules())
                    {
                        if (ruleName != null && rule.Name != ruleName)
                        {
                            continue;
                        }
                        var metadata = ReadMetadata(rule);
                        if (expiredOnly && (metadata == null || metadata.ExpiresAt > now))
                        {
                            continue;
                        }
                        if (_firewall != null && OperatingSystem.IsWindows())
                        {
                            _firewall.Remove(rule.Name);
                        }
                        else
                        {
                            _rules.Remove(rule.Name);
                        }
                        removed++;
                        string reason = expiredOnly ? "expired" : "manual";
                        _logger.LogInformation("Removed rule {RuleName} for {Ip}, alert {AlertId}, reason {Reason}, dry-run {DryRun}",
                            rule.Name, rule.RemoteAddress, metadata?.AlertId, reason, IsDryRun);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Cannot remove firewall rules");
                }
            }
            return removed;
        }

        private List<FirewallStoredRule> GetRules()
        {
            if (_firewall != null && OperatingSystem.IsWindows())
            {
                return _firewall.List();
            }
            return _rules.Values.ToList();
        }

        private FirewallRuleMetadata? ReadMetadata(FirewallStoredRule rule)
        {
            try
            {
                var metadata = JsonSerializer.Deserialize<FirewallRuleMetadata>(rule.Description, JsonOptions);
                if (metadata != null && metadata.AlertId != Guid.Empty &&
                    rule.Name == FirewallRuleNaming.BuildRuleName(metadata.AlertId) &&
                    NormalizeIp(metadata.Ip) != null && NormalizeIp(metadata.Ip) == NormalizeIp(rule.RemoteAddress, true) &&
                    metadata.CreatedAt != default && metadata.ExpiresAt > metadata.CreatedAt &&
                    float.IsFinite(metadata.Confidence) && metadata.Confidence >= 0 && metadata.Confidence <= 1)
                {
                    return metadata;
                }
            }
            catch (JsonException)
            {
                // 无效元数据仍可手动删除
                // Invalid metadata can still be removed manually
            }
            _logger.LogWarning("Cannot read expiry metadata for {RuleName}", rule.Name);
            return null;
        }

        private static string? NormalizeIp(string value, bool fromRule = false)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }
            var parts = value.Split('/');
            if (!IPAddress.TryParse(parts[0], out var address))
            {
                return null;
            }
            // Windows 规则地址可能带完整主机掩码
            // Windows rule addresses may include a full host mask
            if (parts.Length > 1)
            {
                if (!fromRule || parts.Length != 2)
                {
                    return null;
                }
                bool ipv4Host = address.AddressFamily == AddressFamily.InterNetwork &&
                    (parts[1] == "32" || parts[1] == "255.255.255.255");
                bool ipv6Host = address.AddressFamily == AddressFamily.InterNetworkV6 && parts[1] == "128";
                if (!ipv4Host && !ipv6Host)
                {
                    return null;
                }
            }
            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }
            return address.ToString();
        }
    }

    // 序列化到 Description 的审计信息
    // Audit details serialized into Description
    internal class FirewallRuleMetadata
    {
        public Guid AlertId { get; set; }
        public string Ip { get; set; } = string.Empty;
        public string AttackType { get; set; } = string.Empty;
        public float Confidence { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }
    }
}

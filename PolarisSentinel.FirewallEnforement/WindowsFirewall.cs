using System.Net;
using System.Runtime.Versioning;
using PolarisSentinel.Core.Constants;

namespace PolarisSentinel.FirewallEnforement
{
    // Windows 防火墙 COM 封装
    // COM wrapper for Windows Firewall
    [SupportedOSPlatform("windows")]
    internal class WindowsFirewall
    {
        private readonly dynamic _rules;

        public WindowsFirewall()
        {
            var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (type == null)
            {
                throw new InvalidOperationException("Windows Firewall COM is unavailable.");
            }
            dynamic policy = Activator.CreateInstance(type)!;
            _rules = policy.Rules;
        }

        public void Save(FirewallStoredRule rule)
        {
            CheckName(rule.Name);

            // "*" means Any; otherwise one or more comma-separated addresses or CIDR
            // subnets are allowed (Windows Firewall accepts both forms).
            string remoteAddresses = NormalizeRemoteAddresses(rule.RemoteAddress);

            object? existing = null;
            foreach (dynamic item in _rules)
            {
                if (string.Equals((string)item.Name, rule.Name, StringComparison.Ordinal))
                {
                    existing = item;
                    break;
                }
            }

            dynamic target;
            if (existing != null)
            {
                target = existing;
            }
            else
            {
                var type = Type.GetTypeFromProgID("HNetCfg.FWRule")!;
                target = Activator.CreateInstance(type)!;
            }

            target.Name = rule.Name;
            // 256 = any protocol; 0 is not a valid Windows Firewall protocol value.
            target.Protocol = rule.Protocol == 0 ? 256 : rule.Protocol;
            target.RemoteAddresses = remoteAddresses;
            target.Direction = rule.Direction;
            target.Action = 0;
            target.Profiles = int.MaxValue;
            target.Enabled = rule.Enabled;

            SetPorts(target, rule);

            // Update the existing rule when extending; do not Add again.
            if (existing == null)
            {
                _rules.Add(target);
            }
        }

        // Accepts "*", a single address, a CIDR subnet, or a comma-separated list of
        // addresses/subnets. Invalid entries are rejected so a malformed rule never
        // silently degrades into an "any address" block.
        internal static string NormalizeRemoteAddresses(string value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Trim() == "*")
            {
                return "*";
            }

            var parts = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var normalized = new List<string>(parts.Length);
            foreach (var part in parts)
            {
                if (!TryNormalizeAddress(part, out var address))
                {
                    throw new ArgumentException($"Invalid remote address '{part}'.");
                }
                normalized.Add(address);
            }

            return normalized.Count == 0 ? "*" : string.Join(",", normalized);
        }

        // A CIDR subnet keeps its prefix; a bare address keeps its normalized form.
        private static bool TryNormalizeAddress(string value, out string normalized)
        {
            normalized = string.Empty;
            var segments = value.Split('/');
            if (segments.Length > 2 || !IPAddress.TryParse(segments[0], out var address))
            {
                return false;
            }

            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }

            if (segments.Length == 2)
            {
                if (!int.TryParse(segments[1], out int prefix) || prefix < 0 || prefix > 128)
                {
                    return false;
                }
                normalized = $"{address}/{prefix}";
            }
            else
            {
                normalized = address.ToString();
            }

            return true;
        }

        // Windows Firewall uses "*" for every port; 0 means "not specified".
        // A port filter cannot be combined with the Any protocol, so that combination
        // is rejected rather than silently widened into an all-port block.
        private static void SetPorts(dynamic target, FirewallStoredRule rule)
        {
            bool anyProtocol = rule.Protocol == 0;
            if (anyProtocol && (rule.LocalPort != 0 || rule.RemotePort != 0))
            {
                throw new ArgumentException(
                    "A port filter cannot be applied with the Any protocol; specify TCP or UDP.");
            }

            target.LocalPorts = rule.LocalPort == 0 ? "*" : rule.LocalPort.ToString();
            target.RemotePorts = rule.RemotePort == 0 ? "*" : rule.RemotePort.ToString();
        }

        public void Remove(string ruleName)
        {
            CheckName(ruleName);
            _rules.Remove(ruleName);
        }

        private static void CheckName(string name)
        {
            if (string.IsNullOrEmpty(name) || !name.StartsWith(EntityIds.FirewallRulePrefix, StringComparison.Ordinal))
            {
                throw new ArgumentException("Only PolarisSentinel rules can be changed.");
            }
        }
    }

    internal class FirewallStoredRule
    {
        public string Name { get; set; } = string.Empty;
        public string RemoteAddress { get; set; } = string.Empty;
        public int LocalPort { get; set; }
        public int RemotePort { get; set; }
        public byte Protocol { get; set; }
        public bool Enabled { get; set; } = true;
        public bool IsBlockRule { get; set; } = true;
        public int Direction { get; set; } = 1;
    }
}

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

            // "*" means Any; otherwise a single remote IP is required.
            string remoteAddresses;
            if (rule.RemoteAddress == "*")
            {
                remoteAddresses = "*";
            }
            else if (IPAddress.TryParse(rule.RemoteAddress, out var address))
            {
                remoteAddresses = address.ToString();
            }
            else
            {
                throw new ArgumentException("A single remote IP address is required.");
            }

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
            target.Direction = 1;
            target.Action = 0;
            target.Profiles = int.MaxValue;
            target.Enabled = rule.Enabled;

            // A port of 0 (or a protocol of Any) cannot be expressed, so the port
            // filter is left unset and the rule matches every port.
            SetPorts(target, rule);

            // Update the existing rule when extending; do not Add again.
            if (existing == null)
            {
                _rules.Add(target);
            }
        }

        // Windows Firewall uses "*" for every port; 0 means "not specified".
        private static void SetPorts(dynamic target, FirewallStoredRule rule)
        {
            bool anyProtocol = rule.Protocol == 0;
            target.LocalPorts = anyProtocol || rule.LocalPort == 0 ? "*" : rule.LocalPort.ToString();
            target.RemotePorts = anyProtocol || rule.RemotePort == 0 ? "*" : rule.RemotePort.ToString();
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

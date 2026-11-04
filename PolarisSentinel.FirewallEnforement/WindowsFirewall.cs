using System.Runtime.Versioning;
using PolarisSentinel.Core.Constants;

namespace PolarisSentinel.FirewallEnforement
{
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
            target.Protocol = rule.Protocol == 0 ? 256 : rule.Protocol;
            SetPorts(target, rule);
            target.RemoteAddresses = rule.RemoteAddress;
            target.Direction = rule.Direction;
            target.Action = 0;
            target.Profiles = int.MaxValue;
            target.Enabled = rule.Enabled;

            if (existing == null)
            {
                _rules.Add(target);
            }
        }

        private static void SetPorts(dynamic target, FirewallStoredRule rule)
        {
            bool portCapable = rule.Protocol is ProtocolNumbers.Tcp or ProtocolNumbers.Udp;
            if (!portCapable)
            {
                if (rule.LocalPort != 0 || rule.RemotePort != 0)
                {
                    throw new ArgumentException(
                        "A port filter requires the TCP or UDP protocol.");
                }
                return;
            }

            target.LocalPorts = rule.LocalPort == 0 ? "*" : rule.LocalPort.ToString();
            target.RemotePorts = rule.RemotePort == 0 ? "*" : rule.RemotePort.ToString();
        }

        public void Remove(string ruleName)
        {
            CheckName(ruleName);
            foreach (dynamic rule in _rules)
            {
                if (string.Equals((string)rule.Name, ruleName, StringComparison.Ordinal))
                {
                    _rules.Remove(ruleName);
                    return;
                }
            }
        }

        public IReadOnlyList<string> ListManagedNames()
        {
            var names = new List<string>();
            foreach (dynamic rule in _rules)
            {
                string name = (string)rule.Name;
                if (!string.IsNullOrEmpty(name) &&
                    name.StartsWith(EntityIds.FirewallRulePrefix, StringComparison.Ordinal))
                {
                    names.Add(name);
                }
            }
            return names;
        }

        private static void CheckName(string name)
        {
            if (string.IsNullOrEmpty(name) || !name.StartsWith(EntityIds.FirewallRulePrefix, StringComparison.Ordinal))
            {
                throw new ArgumentException("Only PolarisSentinel rules can be changed.");
            }
        }

        public IReadOnlyList<string> GetBlockedInboundAddresses()
        {
            var addresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (dynamic rule in _rules)
            {
                string name = (string)rule.Name;
                if (!name.StartsWith(EntityIds.FirewallRulePrefix, StringComparison.Ordinal) ||
                    !(bool)rule.Enabled || (int)rule.Direction != 1 ||
                    (int)rule.Action != 0 || (int)rule.Protocol != 256)
                    continue;

                foreach (string value in ((string)rule.RemoteAddresses).Split(','))
                {
                    if (NetworkAddress.TryNormalize(value.Trim(), out var address))
                        addresses.Add(address);
                }
            }
            return addresses.ToArray();
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
        public int Direction { get; set; } = 1;
    }
}

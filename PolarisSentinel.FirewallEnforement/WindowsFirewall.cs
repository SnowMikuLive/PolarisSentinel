using System.Net;
using System.Runtime.Versioning;
using PolarisSentinel.Core.Constants;

namespace PolarisSentinel.FirewallEnforement
{
    //Windows防火墙COM封装
    //COM wrapper for Windows Firewall
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
            if (!IPAddress.TryParse(rule.RemoteAddress, out var address))
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
            target.Protocol = 256;
            target.RemoteAddresses = address.ToString();
            target.Direction = 1;
            target.Action = 0;
            target.Profiles = int.MaxValue;
            target.Description = rule.Description;
            target.Enabled = true;

            //续期时更新已有规则，不重复Add
            //Update the existing rule when extending; do not Add again
            if (existing == null)
            {
                _rules.Add(target);
            }
        }

        public void Remove(string ruleName)
        {
            CheckName(ruleName);
            _rules.Remove(ruleName);
        }

        public List<FirewallStoredRule> List()
        {
            var result = new List<FirewallStoredRule>();
            foreach (dynamic rule in _rules)
            {
                string name = rule.Name;
                if (name.StartsWith(EntityIds.FirewallRulePrefix, StringComparison.Ordinal))
                {
                    result.Add(new FirewallStoredRule
                    {
                        Name = name,
                        RemoteAddress = rule.RemoteAddresses,
                        Description = rule.Description,
                        Enabled = rule.Enabled,
                        IsBlockRule = rule.Action == 0,
                        Direction = rule.Direction
                    });
                }
            }
            return result;
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
        public string Description { get; set; } = string.Empty;
        public bool Enabled { get; set; } = true;
        public bool IsBlockRule { get; set; } = true;
        public int Direction { get; set; } = 1;
    }
}

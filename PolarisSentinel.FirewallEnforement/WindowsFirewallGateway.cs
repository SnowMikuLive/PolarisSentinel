using System.Security.Principal;
using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.FirewallEnforement
{
    // Singleton that owns the Windows Firewall COM handle, so COM and the admin check are
    // done once per process instead of once per processed flow.
    public sealed class WindowsFirewallGateway : IFirewallGateway
    {
        private readonly FirewallRuntimeState _state;
        private readonly ILogger<WindowsFirewallGateway> _logger;
        private readonly object _lock = new();

        private WindowsFirewall? _firewall;
        private string? _disabledReason;

        public WindowsFirewallGateway(FirewallRuntimeState state, ILogger<WindowsFirewallGateway> logger)
        {
            _state = state;
            _logger = logger;
            Reevaluate();
        }

        public bool IsEnabled
        {
            get
            {
                lock (_lock)
                {
                    return _firewall != null;
                }
            }
        }

        public string? DisabledReason
        {
            get
            {
                lock (_lock)
                {
                    return _disabledReason;
                }
            }
        }

        public void Reevaluate()
        {
            lock (_lock)
            {
                if (_state.DryRun)
                {
                    Disable("disabled (dry-run enabled from the dashboard)");
                    return;
                }

                try
                {
                    if (!OperatingSystem.IsWindows())
                    {
                        Disable("Windows Firewall is unavailable on this platform", error: true);
                        return;
                    }

                    using var identity = WindowsIdentity.GetCurrent();
                    var principal = new WindowsPrincipal(identity);
                    if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                    {
                        Disable("administrator rights are required", error: true);
                        return;
                    }

                    _firewall = new WindowsFirewall();
                    _disabledReason = null;
                    _logger.LogInformation("Real Windows Firewall execution enabled");
                }
                catch (Exception ex)
                {
                    _firewall = null;
                    _disabledReason = "Windows Firewall could not be opened";
                    _logger.LogError(ex, "Firewall DRY-RUN: {Reason}. Detections are recorded but NOT blocked.", _disabledReason);
                }
            }
        }

        private void Disable(string reason, bool error = false)
        {
            _firewall = null;
            _disabledReason = reason;
            if (error)
            {
                _logger.LogError("Firewall DRY-RUN: {Reason}. Detections are recorded but NOT blocked.", reason);
            }
            else
            {
                _logger.LogWarning("Firewall DRY-RUN: {Reason}. Detections are recorded but NOT blocked.", reason);
            }
        }

        public bool Apply(string ruleName, FirewallRuleSpec spec, bool ruleActive)
        {
            lock (_lock)
            {
                if (_firewall == null || !OperatingSystem.IsWindows())
                {
                    return false;
                }

                string? ip = string.IsNullOrWhiteSpace(spec.RemoteAddress)
                    ? "*"
                    : NormalizeIp(spec.RemoteAddress!);
                if (ip == null)
                {
                    _logger.LogWarning("Cannot apply rule {RuleName}: invalid address {Address}", ruleName, spec.RemoteAddress);
                    return false;
                }

                _firewall.Save(new FirewallStoredRule
                {
                    Name = ruleName,
                    RemoteAddress = ip,
                    LocalPort = spec.LocalPort ?? 0,
                    RemotePort = spec.RemotePort ?? 0,
                    Protocol = spec.Protocol,
                    Enabled = ruleActive,
                    Direction = spec.Direction
                });

                _logger.LogInformation(
                    "Windows Firewall rule written: {RuleName} direction={Direction} protocol={Protocol} localPorts={LocalPorts} remotePorts={RemotePorts} remoteAddresses={RemoteAddresses}",
                    ruleName, spec.Direction,
                    spec.Protocol == 0 ? "Any" : spec.Protocol.ToString(),
                    spec.LocalPort?.ToString() ?? "Any",
                    spec.RemotePort?.ToString() ?? "Any",
                    ip);
                return true;
            }
        }

        public void Remove(string ruleName)
        {
            if (string.IsNullOrEmpty(ruleName) || !OperatingSystem.IsWindows())
            {
                return;
            }

            lock (_lock)
            {
                var firewall = _firewall ?? new WindowsFirewall();
                firewall.Remove(ruleName);
            }
        }

        public IReadOnlyList<string> ListManagedNames()
        {
            if (!OperatingSystem.IsWindows())
            {
                return Array.Empty<string>();
            }

            lock (_lock)
            {
                return _firewall?.ListManagedNames() ?? Array.Empty<string>();
            }
        }

        private static string? NormalizeIp(string value) =>
            NetworkAddress.TryNormalize(value, out var normalized) ? normalized : null;
    }
}

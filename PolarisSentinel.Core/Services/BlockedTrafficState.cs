using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Services;

// The addresses an active rule currently blocks. Windows Firewall drops their traffic, but
// the capture driver sits below the firewall, so the packets still arrive: this registry is
// what lets the pipeline report them as dropped instead of analysing them again.
public sealed class BlockedTrafficState
{
    private readonly object _lock = new();
    private HashSet<string> _addresses = new(StringComparer.OrdinalIgnoreCase);

    public bool IsBlocked(string? ip)
    {
        if (string.IsNullOrEmpty(ip))
        {
            return false;
        }

        lock (_lock)
        {
            return _addresses.Contains(ip);
        }
    }

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _addresses.Count;
            }
        }
    }

    // Replaces the registry with the addresses the active rules block. Called by the sweeper,
    // so a rule that expired stops marking traffic as blocked.
    public void Refresh(IEnumerable<Rule> rules)
    {
        var addresses = rules
            .Where(r => r.Status == RuleStatus.Active && r.BlocksAddress && !string.IsNullOrEmpty(r.BlockedIp))
            .Select(r => r.BlockedIp!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        lock (_lock)
        {
            _addresses = addresses;
        }
    }

    public void Add(string? address)
    {
        if (string.IsNullOrEmpty(address))
        {
            return;
        }

        lock (_lock)
        {
            _addresses.Add(address);
        }
    }
}
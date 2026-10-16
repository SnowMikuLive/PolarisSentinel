using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Services;

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

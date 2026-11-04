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

    public void Refresh(IEnumerable<string> blockedAddresses)
    {
        var addresses = blockedAddresses
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        lock (_lock)
        {
            _addresses = addresses;
        }
    }

}

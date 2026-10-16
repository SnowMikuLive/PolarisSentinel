using System.Net;
using System.Net.Sockets;

namespace PolarisSentinel.Core.Constants;

public static class NetworkAddress
{
    public static bool TryNormalize(string value, out string normalized)
    {
        normalized = string.Empty;
        if (!IPAddress.TryParse(value, out var address) ||
            address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        normalized = address.ToString();
        return true;
    }

    public static bool IsValid(string? value) =>
        !string.IsNullOrWhiteSpace(value) && TryNormalize(value, out _);
}

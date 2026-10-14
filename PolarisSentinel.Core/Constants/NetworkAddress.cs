using System.Net;
using System.Net.Sockets;

namespace PolarisSentinel.Core.Constants;

// Platform-neutral parsing of IPv4 addresses, shared by the domain (rule validation)
// and the firewall layer (address normalisation). Only IPv4 is supported; CIDR subnets
// and IPv6 are out of scope.
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

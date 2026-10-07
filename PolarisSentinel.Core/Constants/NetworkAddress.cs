using System.Net;
using System.Net.Sockets;

namespace PolarisSentinel.Core.Constants;

// Platform-neutral parsing of IP addresses and CIDR subnets, shared by the domain
// (rule validation) and the firewall layer (address normalisation).
public static class NetworkAddress
{
    // A CIDR subnet keeps its prefix; a bare address keeps its normalized form.
    public static bool TryNormalize(string value, out string normalized)
    {
        normalized = string.Empty;
        var segments = value.Split('/');
        if (segments.Length > 2 || !IPAddress.TryParse(segments[0], out var address))
        {
            return false;
        }

        if (segments.Length == 2)
        {
            int maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (!int.TryParse(segments[1], out int prefix) || prefix < 0 || prefix > maxPrefix)
            {
                return false;
            }
            normalized = $"{address}/{prefix}";
        }
        else
        {
            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }
            normalized = address.ToString();
        }

        return true;
    }

    // True when the value is empty (meaning "any") or a valid address/CIDR.
    public static bool IsValidOrEmpty(string? value) =>
        string.IsNullOrWhiteSpace(value) || TryNormalize(value, out _);
}

using System.Net;

namespace PolarisSentinel.PolicyDecision;

// 私网和配置中的地址只监控。
// Monitor private and configured addresses without blocking them.
internal static class AddressAllowlist
{
    private static readonly string[] BuiltIn =
    {
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "0.0.0.0/32",
        "::1/128", "::/128", "fe80::/10", "fc00::/7", "ff00::/8"
    };

    public static bool Contains(string sourceIp, string[] configured)
    {
        // 无效地址也不能交给防火墙。
        // Invalid addresses must not reach the firewall either.
        if (!IPAddress.TryParse(sourceIp, out var address)) return true;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        foreach (var entry in BuiltIn.Concat(configured))
        {
            if (IPNetwork.TryParse(entry, out var network) && network.Contains(address)) return true;
            if (IPAddress.TryParse(entry, out var ip))
            {
                if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
                if (ip.Equals(address)) return true;
            }
        }
        return false;
    }
}

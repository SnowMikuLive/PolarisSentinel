using System.Net;

namespace PolarisSentinel.FirewallEnforement
{
    // Platform-neutral normalisation of IP addresses and CIDR subnets used by the
    // firewall layer. Kept separate from WindowsFirewall so address handling is not
    // tied to the Windows-only COM wrapper.
    internal static class AddressNormalizer
    {
        // Accepts "*", a single address, a CIDR subnet, or a comma-separated list of
        // addresses/subnets. Invalid entries are rejected so a malformed rule never
        // silently degrades into an "any address" block.
        public static string NormalizeRemoteAddresses(string value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Trim() == "*")
            {
                return "*";
            }

            var parts = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var normalized = new List<string>(parts.Length);
            foreach (var part in parts)
            {
                if (!TryNormalizeAddress(part, out var address))
                {
                    throw new ArgumentException($"Invalid remote address '{part}'.");
                }
                normalized.Add(address);
            }

            return normalized.Count == 0 ? "*" : string.Join(",", normalized);
        }

        // A CIDR subnet keeps its prefix; a bare address keeps its normalized form.
        public static bool TryNormalizeAddress(string value, out string normalized)
        {
            normalized = string.Empty;
            var segments = value.Split('/');
            if (segments.Length > 2 || !IPAddress.TryParse(segments[0], out var address))
            {
                return false;
            }

            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }

            if (segments.Length == 2)
            {
                if (!int.TryParse(segments[1], out int prefix) || prefix < 0 || prefix > 128)
                {
                    return false;
                }
                normalized = $"{address}/{prefix}";
            }
            else
            {
                normalized = address.ToString();
            }

            return true;
        }
    }
}

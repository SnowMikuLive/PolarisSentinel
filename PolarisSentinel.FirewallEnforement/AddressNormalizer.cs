using PolarisSentinel.Core.Constants;

namespace PolarisSentinel.FirewallEnforement
{
    // Normalisation of IP addresses and CIDR subnets for the firewall layer. Parsing lives
    // in Core's NetworkAddress so the domain and firewall share one implementation.
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
                if (!NetworkAddress.TryNormalize(part, out var address))
                {
                    throw new ArgumentException($"Invalid remote address '{part}'.");
                }
                normalized.Add(address);
            }

            return normalized.Count == 0 ? "*" : string.Join(",", normalized);
        }
    }
}

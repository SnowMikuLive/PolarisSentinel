using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace PolarisSentinel.PolicyDecision
{
    //内置和用户配置的白名单
    //Built-in and configured allowlist
    public class AddressAllowlist
    {
        private static readonly string[] BuiltInEntries =
        {
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "255.255.255.255/32",
            "::1/128",
            "fe80::/10",
            "fc00::/7"
        };

        private readonly List<AddressRange> _ranges;
        private readonly ILogger _logger;

        public AddressAllowlist(IEnumerable<string>? configuredEntries, ILogger logger)
        {
            if (logger == null)
            {
                throw new ArgumentNullException(nameof(logger));
            }

            _logger = logger;
            _ranges = new List<AddressRange>();

            foreach (var entry in BuiltInEntries)
            {
                if (TryParseRange(entry, out var range))
                {
                    _ranges.Add(range);
                }
            }

            foreach (var entry in configuredEntries ?? Array.Empty<string>())
            {
                if (TryParseRange(entry, out var range))
                {
                    _ranges.Add(range);
                }
                else
                {
                    _logger.LogWarning("Ignoring invalid allowlist entry {AllowlistEntry}.", entry);
                }
            }
        }

        public bool Contains(string? address)
        {
            if (!IPAddress.TryParse(address, out var parsedAddress))
            {
                _logger.LogWarning("Cannot check invalid source IP {SourceIp} against the allowlist.", address);
                return false;
            }

            //映射地址按IPv4检查
            //Check mapped addresses as IPv4
            if (parsedAddress.IsIPv4MappedToIPv6)
            {
                parsedAddress = parsedAddress.MapToIPv4();
            }

            var bytes = parsedAddress.GetAddressBytes();
            foreach (var range in _ranges)
            {
                if (range.Contains(bytes))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool TryParseRange(string? entry, out AddressRange range)
        {
            range = null!;
            if (string.IsNullOrWhiteSpace(entry))
            {
                return false;
            }

            var parts = entry.Split('/');
            if (parts.Length > 2 || !IPAddress.TryParse(parts[0].Trim(), out var address))
            {
                return false;
            }

            int addressBits;
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                addressBits = 32;
            }
            else if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                addressBits = 128;
            }
            else
            {
                return false;
            }

            int prefixLength = addressBits;
            if (parts.Length == 2)
            {
                if (!int.TryParse(parts[1].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out prefixLength))
                {
                    return false;
                }

                if (prefixLength < 0 || prefixLength > addressBits)
                {
                    return false;
                }
            }

            if (address.IsIPv4MappedToIPv6)
            {
                if (prefixLength < 96)
                {
                    return false;
                }

                address = address.MapToIPv4();
                prefixLength -= 96;
            }

            range = new AddressRange(address.GetAddressBytes(), prefixLength);
            return true;
        }

        private class AddressRange
        {
            private readonly byte[] _address;
            private readonly int _prefixLength;

            public AddressRange(byte[] address, int prefixLength)
            {
                _address = address;
                _prefixLength = prefixLength;
            }

            public bool Contains(byte[] candidate)
            {
                if (candidate.Length != _address.Length)
                {
                    return false;
                }

                //只比较网络前缀
                //Compare only the network prefix
                int fullBytes = _prefixLength / 8;
                for (int i = 0; i < fullBytes; i++)
                {
                    if (candidate[i] != _address[i])
                    {
                        return false;
                    }
                }

                int remainingBits = _prefixLength % 8;
                if (remainingBits == 0)
                {
                    return true;
                }

                int mask = 255 << (8 - remainingBits);
                return (candidate[fullBytes] & mask) == (_address[fullBytes] & mask);
            }
        }
    }
}

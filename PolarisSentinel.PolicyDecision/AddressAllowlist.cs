using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace PolarisSentinel.PolicyDecision;

// 受保护地址范围的不可变快照，含内置私有网段和用户配置的白名单。
// Immutable snapshot of protected address ranges, including built-in private ranges and user allowlist.
public sealed class AddressAllowlist
{
    // 内置保护范围：回环、RFC 1918 私有网、链路本地、组播等
    // Built-in protected ranges: loopback, RFC 1918 private, link-local, multicast, etc.
    private static readonly string[] BuiltInEntries =
    [
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
    ];

    private readonly AddressRange[] _ranges;
    private readonly ILogger _logger;

    public AddressAllowlist(IEnumerable<string>? configuredEntries, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;

        var ranges = new List<AddressRange>();
        foreach (var entry in BuiltInEntries)
        {
            if (TryParseRange(entry, out var range))
                ranges.Add(range);
        }

        foreach (var entry in configuredEntries ?? [])
        {
            if (TryParseRange(entry, out var range))
                ranges.Add(range);
            else
                _logger.LogWarning("Ignoring invalid allowlist entry {AllowlistEntry}.", entry);
        }

        _ranges = ranges.ToArray();
    }

    public bool Contains(string? address)
    {
        if (!IPAddress.TryParse(address, out var parsedAddress))
        {
            _logger.LogWarning("Cannot check invalid source IP {SourceIp} against the allowlist.", address);
            return false;
        }

        // 将 IPv4-mapped IPv6 地址规范化为 IPv4，防止私有地址绕过保护
        // Treat mapped addresses as IPv4 so private addresses cannot bypass protection
        if (parsedAddress.IsIPv4MappedToIPv6)
            parsedAddress = parsedAddress.MapToIPv4();

        var bytes = parsedAddress.GetAddressBytes();
        foreach (var range in _ranges)
        {
            if (range.Contains(bytes))
                return true;
        }

        return false;
    }

    private static bool TryParseRange(string? entry, out AddressRange range)
    {
        range = null!;
        if (string.IsNullOrWhiteSpace(entry))
            return false;

        var parts = entry.Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0].Trim(), out var address))
            return false;

        var addressBits = address.AddressFamily switch
        {
            AddressFamily.InterNetwork => 32,
            AddressFamily.InterNetworkV6 => 128,
            _ => 0
        };
        if (addressBits == 0)
            return false;

        var prefixLength = addressBits;
        if (parts.Length == 2 &&
            (!int.TryParse(parts[1].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out prefixLength) ||
             prefixLength < 0 || prefixLength > addressBits))
            return false;

        if (address.IsIPv4MappedToIPv6)
        {
            // mapped CIDR 必须先落在 mapped IPv4 块内，再规范化
            // A mapped CIDR must stay within the mapped IPv4 block before normalization
            if (prefixLength < 96)
                return false;

            address = address.MapToIPv4();
            prefixLength -= 96;
        }

        range = new AddressRange(address.GetAddressBytes(), prefixLength);
        return true;
    }

    private sealed class AddressRange(byte[] address, int prefixLength)
    {
        private readonly byte[] _address = address;
        private readonly int _wholeBytes = prefixLength / 8;
        private readonly int _partialMask = (0xff << (8 - prefixLength % 8)) & 0xff;

        public bool Contains(byte[] candidate)
        {
            // 字节长度不同则 IPv4 与 IPv6 范围不会交叉匹配
            // Byte length also ensures that IPv4 and IPv6 ranges never cross-match
            if (candidate.Length != _address.Length ||
                !candidate.AsSpan(0, _wholeBytes).SequenceEqual(_address.AsSpan(0, _wholeBytes)))
                return false;

            return _partialMask == 0 ||
                   (candidate[_wholeBytes] & _partialMask) == (_address[_wholeBytes] & _partialMask);
        }
    }
}

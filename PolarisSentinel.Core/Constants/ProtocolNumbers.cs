namespace PolarisSentinel.Core.Constants;

public static class ProtocolNumbers
{
    public const byte Tcp = 6;
    public const byte Udp = 17;
    public const byte Icmp = 1;

    // Readable name for an IP protocol number; 0/null mean "Any".
    public static string Name(byte? protocol) => protocol switch
    {
        Icmp => "ICMP",
        Tcp => "TCP",
        Udp => "UDP",
        0 or null => "Any",
        _ => protocol.Value.ToString()
    };
}

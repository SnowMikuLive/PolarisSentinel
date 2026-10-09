namespace PolarisSentinel.Core.Constants;

public static class ProtocolNumbers
{
    public const byte Tcp = 6;
    public const byte Udp = 17;
    public const byte Icmp = 1;

    public static string Name(byte? protocol) => protocol switch
    {
        Icmp => "ICMP",
        Tcp => "TCP",
        Udp => "UDP",
        0 or null => "Any",
        _ => protocol.Value.ToString()
    };
}

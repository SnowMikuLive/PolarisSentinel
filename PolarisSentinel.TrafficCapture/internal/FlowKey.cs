namespace PolarisSentinel.TrafficCapture.Internal;


internal sealed class FlowKey : IEquatable<FlowKey>
{
    public required string IpA { get; init; }
    public required ushort PortA { get; init; }
    public required string IpB { get; init; }
    public required ushort PortB { get; init; }
    public required byte Protocol { get; init; }

    public static FlowKey Create(string ip1, ushort port1, string ip2, ushort port2, byte protocol)
    {
        bool ip1IsLower = string.CompareOrdinal(ip1, ip2) <= 0;
        return ip1IsLower
            ? new FlowKey { IpA = ip1, PortA = port1, IpB = ip2, PortB = port2, Protocol = protocol }
            : new FlowKey { IpA = ip2, PortA = port2, IpB = ip1, PortB = port1, Protocol = protocol };
    }

    public bool Equals(FlowKey? other) =>
        other is not null &&
        IpA == other.IpA && IpB == other.IpB &&
        PortA == other.PortA && PortB == other.PortB &&
        Protocol == other.Protocol;

    public override bool Equals(object? obj) => Equals(obj as FlowKey);

    public override int GetHashCode() => HashCode.Combine(IpA, IpB, PortA, PortB, Protocol);
}

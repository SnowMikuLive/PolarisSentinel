namespace PolarisSentinel.Core.Models;
public class LiveTrafficSummary
{
    public required DateTime Timestamp { get; init; }
    public required double PacketsPerSecond { get; init; }
    public required double BytesPerSecond { get; init; }
    public required int ActiveFlowCount { get; init; }
    public required double TcpShare { get; init; }
    public required double UdpShare { get; init; }
    public required double IcmpShare { get; init; }
}

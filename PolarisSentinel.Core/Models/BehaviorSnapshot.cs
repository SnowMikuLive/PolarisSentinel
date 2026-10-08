namespace PolarisSentinel.Core.Models;

// Aggregate window statistics behind a behavioural (Heuristic) verdict, so the alert
// detail page can show why a source was flagged.
public static class BehaviorSnapshot
{
    public static string Create(BehaviorWindowStats stats)
    {
        var values = new Dictionary<string, float>
        {
            ["packets"] = stats.TotalPackets,
            ["distinct_ports"] = stats.DistinctPorts,
            ["distinct_destinations"] = stats.DistinctDestinationIps,
            ["syn"] = stats.SynCount,
            ["ack"] = stats.AckCount,
            ["icmp"] = stats.IcmpCount,
            ["auth_connections"] = stats.AuthConnections,
            ["window_seconds"] = (float)stats.WindowSeconds
        };

        return SnapshotJson.Serialize(values);
    }

    public static IReadOnlyList<KeyValuePair<string, float>> Read(string? json) =>
        SnapshotJson.Read(json).ToList();
}

// The aggregate counters of one source's sliding window at verdict time.
public sealed record BehaviorWindowStats(
    int TotalPackets,
    int DistinctPorts,
    int DistinctDestinationIps,
    int SynCount,
    int AckCount,
    int IcmpCount,
    int AuthConnections,
    double WindowSeconds);

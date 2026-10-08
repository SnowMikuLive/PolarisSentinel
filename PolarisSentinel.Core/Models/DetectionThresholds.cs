using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// Single source of truth for every heuristic detection threshold. A preset is selected
// by DetectionSensitivity; individual values can still be overridden from configuration
// (see Resolve) without touching code. Lower numbers mean more sensitive.
public sealed record DetectionThresholds
{
    // --- PreFilter: single-flow signatures (reported as Suspicious for the AI to confirm) ---
    public int MinPacketsForAnalysis { get; init; }
    public int SynFloodSyns { get; init; }
    public int UdpFloodPackets { get; init; }
    public int UdpFloodPacketsPerSecond { get; init; }
    public int AckFloodAcks { get; init; }
    public int IcmpFloodPackets { get; init; }
    public int IcmpFloodPacketsPerSecond { get; init; }
    public int IcmpPingFloodPackets { get; init; }
    public int IcmpPingFloodPacketsPerSecond { get; init; }
    public int ScanSyns { get; init; }
    public int FinRstScanPackets { get; init; }
    public int UdpScanPackets { get; init; }
    public double UdpScanMaxPayload { get; init; }
    public int IcmpSweepPackets { get; init; }
    public int BruteForceSyns { get; init; }
    public double FlatTrafficStdDev { get; init; }

    // --- PreFilter: relevance gate (which flows are worth sending to the AI engine) ---
    // A flow is forwarded only when it shows a signal relevant to DoS, port scanning or
    // brute force. These are weaker than the attack signatures above: they mark "worth
    // analysing", not "attack". Flows matching none are unrelated traffic and are skipped.
    public int RelevanceMinPackets { get; init; }
    public int RelevanceMinSyns { get; init; }
    public int RelevanceMinAcks { get; init; }

    // --- SourceBehaviorTracker: cross-flow aggregates (KnownAttack -> blocks) ---
    public int PortScanDistinctPorts { get; init; }
    public int PortScanMaxPacketsPerPort { get; init; }
    public int BruteForceConnections { get; init; }
    public int BruteForceMaxPacketsPerAttempt { get; init; }
    public int IcmpFloodSourcePackets { get; init; }
    public int FloodPackets { get; init; }
    public int FloodDistinctPorts { get; init; }
    public int GlobalFloodPackets { get; init; }
    public int GlobalFloodDistinctSources { get; init; }
    public int HostSweepDistinctIps { get; init; }
    public int SynFloodSourceSyns { get; init; }

    // The threshold set for a sensitivity preset.
    public static DetectionThresholds Preset(DetectionSensitivity sensitivity) => sensitivity switch
    {
        DetectionSensitivity.Low => Low,
        DetectionSensitivity.Balanced => Balanced,
        _ => High
    };

    // Applies configuration overrides (null keeps the preset value) on top of a preset.
    public static DetectionThresholds Resolve(
        DetectionSensitivity sensitivity,
        int? minPackets = null,
        int? portScanDistinctPorts = null,
        int? portScanMaxPacketsPerPort = null,
        int? globalFloodPackets = null,
        int? globalFloodDistinctSources = null)
    {
        var preset = Preset(sensitivity);
        return preset with
        {
            MinPacketsForAnalysis = minPackets ?? preset.MinPacketsForAnalysis,
            PortScanDistinctPorts = portScanDistinctPorts ?? preset.PortScanDistinctPorts,
            PortScanMaxPacketsPerPort = portScanMaxPacketsPerPort ?? preset.PortScanMaxPacketsPerPort,
            GlobalFloodPackets = globalFloodPackets ?? preset.GlobalFloodPackets,
            GlobalFloodDistinctSources = globalFloodDistinctSources ?? preset.GlobalFloodDistinctSources
        };
    }

    // Parses a configured sensitivity name; unknown or missing falls back to High.
    public static DetectionSensitivity ParseSensitivity(string? value) =>
        Enum.TryParse<DetectionSensitivity>(value, ignoreCase: true, out var parsed) ? parsed : DetectionSensitivity.High;

    // Maximum sensitivity: tuned for demonstration, where every attack in the test set has to
    // be flagged and blocked. Values are deliberately far below the levels real traffic would
    // tolerate, so an attack is caught within the first packets rather than after a burst.
    public static readonly DetectionThresholds High = new()
    {
        MinPacketsForAnalysis = 2,
        SynFloodSyns = 2,
        UdpFloodPackets = 10,
        UdpFloodPacketsPerSecond = 20,
        AckFloodAcks = 3,
        IcmpFloodPackets = 3,
        IcmpFloodPacketsPerSecond = 3,
        IcmpPingFloodPackets = 3,
        IcmpPingFloodPacketsPerSecond = 3,
        ScanSyns = 1,
        FinRstScanPackets = 0,
        UdpScanPackets = 2,
        UdpScanMaxPayload = 400,
        IcmpSweepPackets = 2,
        BruteForceSyns = 1,
        FlatTrafficStdDev = 10,
        RelevanceMinPackets = 4,
        RelevanceMinSyns = 2,
        RelevanceMinAcks = 2,
        PortScanDistinctPorts = 2,
        PortScanMaxPacketsPerPort = 6,
        BruteForceConnections = 2,
        BruteForceMaxPacketsPerAttempt = 20,
        IcmpFloodSourcePackets = 5,
        FloodPackets = 60,
        FloodDistinctPorts = 3,
        GlobalFloodPackets = 150,
        GlobalFloodDistinctSources = 8,
        HostSweepDistinctIps = 3,
        SynFloodSourceSyns = 8
    };

    // The precision-tuned baseline.
    public static readonly DetectionThresholds Balanced = new()
    {
        MinPacketsForAnalysis = 3,
        SynFloodSyns = 10,
        UdpFloodPackets = 50,
        UdpFloodPacketsPerSecond = 100,
        AckFloodAcks = 20,
        IcmpFloodPackets = 20,
        IcmpFloodPacketsPerSecond = 25,
        IcmpPingFloodPackets = 15,
        IcmpPingFloodPacketsPerSecond = 15,
        ScanSyns = 3,
        FinRstScanPackets = 3,
        UdpScanPackets = 5,
        UdpScanMaxPayload = 200,
        IcmpSweepPackets = 8,
        BruteForceSyns = 3,
        FlatTrafficStdDev = 10,
        RelevanceMinPackets = 50,
        RelevanceMinSyns = 5,
        RelevanceMinAcks = 10,
        PortScanDistinctPorts = 6,
        PortScanMaxPacketsPerPort = 3,
        BruteForceConnections = 5,
        BruteForceMaxPacketsPerAttempt = 8,
        IcmpFloodSourcePackets = 50,
        FloodPackets = 200,
        FloodDistinctPorts = 20,
        GlobalFloodPackets = 1000,
        GlobalFloodDistinctSources = 50,
        HostSweepDistinctIps = 20,
        SynFloodSourceSyns = 100
    };

    // Conservative: only blatant attacks.
    public static readonly DetectionThresholds Low = new()
    {
        MinPacketsForAnalysis = 4,
        SynFloodSyns = 20,
        UdpFloodPackets = 100,
        UdpFloodPacketsPerSecond = 200,
        AckFloodAcks = 40,
        IcmpFloodPackets = 40,
        IcmpFloodPacketsPerSecond = 50,
        IcmpPingFloodPackets = 30,
        IcmpPingFloodPacketsPerSecond = 30,
        ScanSyns = 6,
        FinRstScanPackets = 6,
        UdpScanPackets = 8,
        UdpScanMaxPayload = 200,
        IcmpSweepPackets = 12,
        BruteForceSyns = 5,
        FlatTrafficStdDev = 10,
        RelevanceMinPackets = 100,
        RelevanceMinSyns = 10,
        RelevanceMinAcks = 20,
        PortScanDistinctPorts = 12,
        PortScanMaxPacketsPerPort = 3,
        BruteForceConnections = 8,
        BruteForceMaxPacketsPerAttempt = 8,
        IcmpFloodSourcePackets = 80,
        FloodPackets = 400,
        FloodDistinctPorts = 30,
        GlobalFloodPackets = 2000,
        GlobalFloodDistinctSources = 80,
        HostSweepDistinctIps = 30,
        SynFloodSourceSyns = 200
    };
}

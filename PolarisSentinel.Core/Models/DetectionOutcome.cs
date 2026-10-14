using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// Result of running one flow through the live detection pipeline.
public class DetectionOutcome
{
    public required TrafficVerdict Verdict { get; init; }

    public string Description { get; init; } = string.Empty;

    public Alert? Alert { get; init; }

    public PolicyDecision? Decision { get; init; }

    public Rule? Rule { get; init; }

    public string SourceIp { get; init; } = string.Empty;

    public int SourcePort { get; init; }

    public string DestinationIp { get; init; } = string.Empty;

    public int DestinationPort { get; init; }
}

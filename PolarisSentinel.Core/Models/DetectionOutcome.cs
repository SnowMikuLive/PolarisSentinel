using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// Result of running one flow through the live detection pipeline.
public class DetectionOutcome
{
    // How the flow was finally classified, for the dashboard counters.
    public required TrafficVerdict Verdict { get; init; }

    // Short human-readable explanation of the verdict.
    public string Description { get; init; } = string.Empty;

    // The alert, when the flow produced one. Null for normal and suspicious-but-below-threshold flows.
    public Alert? Alert { get; init; }

    // The policy decision, when an alert was evaluated.
    public PolicyDecision? Decision { get; init; }

    // The firewall rule, when the decision produced one.
    public Rule? Rule { get; init; }

    // The flow's 5-tuple, carried even when there is no Alert (normal/suspicious flows),
    // so the monitor and dashboard can always show source/destination addresses.
    public string SourceIp { get; init; } = string.Empty;

    public int SourcePort { get; init; }

    public string DestinationIp { get; init; } = string.Empty;

    public int DestinationPort { get; init; }
}

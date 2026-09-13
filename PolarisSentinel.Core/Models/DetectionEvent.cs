using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// Persisted record of one detection pipeline run: the detection result and the
// policy decision that followed it. This is the aggregate root for the
// detection/audit bounded context.
public class DetectionEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public required string SourceIp { get; set; }

    public required string DestinationIp { get; set; }

    public int DestinationPort { get; set; }

    public required string AttackType { get; set; }

    public float Confidence { get; set; }

    public PolicyAction Action { get; set; }

    public required string Reason { get; set; }

    public DateTime DecidedAt { get; set; }
}

using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// Stores an AI inference result with the 5-tuple that produced it.
public class Alert
{
    public Guid Id { get; set; } = Guid.NewGuid();

    // 5-tuple
    public required string SourceIp { get; set; }

    public int SourcePort { get; set; }

    public required string DestinationIp { get; set; }

    public int DestinationPort { get; set; }

    public byte Protocol { get; set; }

    // Inference result
    public required string AttackType { get; set; }

    public float Confidence { get; set; }

    public DetectionSource Source { get; set; }

    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}

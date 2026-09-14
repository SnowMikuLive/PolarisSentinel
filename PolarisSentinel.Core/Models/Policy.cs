using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// A policy owned by a user. Defines how detections are handled.
public class Policy
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public required string Name { get; set; }

    public Guid UserId { get; set; }

    public User? User { get; set; }

    public float RfConfidenceThreshold { get; set; } = 0.6f;

    public float AutoBlockConfidenceThreshold { get; set; } = 0.8f;

    public int BlockDurationMinutes { get; set; } = 60;

    public int DecisionCooldownSeconds { get; set; } = 60;

    public bool IsActive { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

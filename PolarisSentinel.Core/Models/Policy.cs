using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

// A policy owned by a user (ASP.NET Identity IdentityUser). Defines how detections are handled.
public class Policy
{
    // Human-readable id, e.g. "P-1".
    public string Id { get; set; } = string.Empty;

    public required string Name { get; set; }

    // Optional free-text description.
    public string? Description { get; set; }

    public string UserId { get; set; } = string.Empty;

    public PolicyAction Action { get; set; } = PolicyAction.Ignore;

    public bool IsActive { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

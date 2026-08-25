using PolarisSentinel.Core.Enums;

namespace PolarisSentinel.Core.Models;

public class DetectionResult
{
    public required string AttackType { get; init; }

    public required float Confidence { get; init; }

    public required DetectionSource Source { get; init; }

    public required string SourceIp { get; init; }
}

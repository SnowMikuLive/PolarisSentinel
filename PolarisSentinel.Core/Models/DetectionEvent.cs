// Replaced by Alert.
namespace PolarisSentinel.Core.Models;
<<<<<<< HEAD

// 单次检测管线的持久化记录
// Persisted record of one detection pipeline run
public class DetectionEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public required string SourceIp { get; set; }

    public required string DestinationIp { get; set; }

    public int DestinationPort { get; set; }

    public required string AttackType { get; set; }

    public float Confidence { get; set; }

    public DetectionSource Source { get; set; }

    public string? RuleName { get; set; }

    public PolicyAction Action { get; set; }

    public required string Reason { get; set; }

    public DateTime DecidedAt { get; set; }
}
=======
>>>>>>> a2e4aeebbed2da61e08be9661cc010e1a59515ad

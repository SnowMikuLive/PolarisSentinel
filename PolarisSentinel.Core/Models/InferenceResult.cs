namespace PolarisSentinel.Core.Models;

// Outcome of one AI engine run: the attack category and the score that produced it.
public class InferenceResult
{
    public required string AttackType { get; init; }

    public float ConfidenceScore { get; init; }

    public string? Description { get; init; }

    public static InferenceResult Benign() => new() { AttackType = Constants.AttackTypes.Benign };

    public static InferenceResult Benign(float benignProbability) =>
        new() { AttackType = Constants.AttackTypes.Benign, ConfidenceScore = benignProbability };
}

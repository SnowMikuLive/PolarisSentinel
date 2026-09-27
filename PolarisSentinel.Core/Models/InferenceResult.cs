namespace PolarisSentinel.Core.Models;

// Outcome of one AI engine run: the attack category and the score that produced it.
public class InferenceResult
{
    public required string AttackType { get; init; }

    // 0..1 where a higher value means stronger malicious evidence.
    // For Random Forest this is the class probability; for Isolation Forest it is a
    // normalized anomaly score (the raw score is not a probability).
    public float ConfidenceScore { get; init; }

    // Short human-readable explanation, e.g. "Isolation Forest anomaly".
    public string? Description { get; init; }

    public static InferenceResult Benign() => new() { AttackType = Constants.AttackTypes.Benign };

    // Benign verdict carrying the classifier's benign probability, for reference comparison.
    public static InferenceResult Benign(float benignProbability) =>
        new() { AttackType = Constants.AttackTypes.Benign, ConfidenceScore = benignProbability };
}

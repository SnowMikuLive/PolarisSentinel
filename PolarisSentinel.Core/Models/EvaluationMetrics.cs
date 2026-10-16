namespace PolarisSentinel.Core.Models;

public class EvaluationMetrics
{
    public int TruePositives { get; init; }

    public int TrueNegatives { get; init; }

    public int FalsePositives { get; init; }

    public int FalseNegatives { get; init; }

    public int Total => TruePositives + TrueNegatives + FalsePositives + FalseNegatives;

    public double? Accuracy => Ratio(TruePositives + TrueNegatives, Total);

    public double? Precision => Ratio(TruePositives, TruePositives + FalsePositives);

    public double? Recall => Ratio(TruePositives, TruePositives + FalseNegatives);

    public double? F1Score
    {
        get
        {
            double? precision = Precision;
            double? recall = Recall;
            if (precision is null || recall is null || precision + recall == 0)
            {
                return null;
            }
            return 2 * precision * recall / (precision + recall);
        }
    }

    public double? FalsePositiveRate => Ratio(FalsePositives, FalsePositives + TrueNegatives);

    public double? FalseNegativeRate => Ratio(FalseNegatives, FalseNegatives + TruePositives);

    private static double? Ratio(int numerator, int denominator) =>
        denominator == 0 ? null : (double)numerator / denominator;
}

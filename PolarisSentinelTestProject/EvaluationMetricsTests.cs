using PolarisSentinel.Core.Models;

namespace PolarisSentienlUnitTestProject;

// Verifies the binary classification metrics, including zero-denominator handling.
[TestClass]
public class EvaluationMetricsTests
{
    [TestMethod]
    public void Metrics_ShouldComputeFromConfusionMatrix()
    {
        var metrics = new EvaluationMetrics
        {
            TruePositives = 80,
            TrueNegatives = 90,
            FalsePositives = 10,
            FalseNegatives = 20
        };

        Assert.AreEqual(200, metrics.Total);
        Assert.AreEqual(0.85, metrics.Accuracy!.Value, 0.0001);
        Assert.AreEqual(80.0 / 90, metrics.Precision!.Value, 0.0001);
        Assert.AreEqual(80.0 / 100, metrics.Recall!.Value, 0.0001);
        Assert.AreEqual(0.1, metrics.FalsePositiveRate!.Value, 0.0001);
        Assert.AreEqual(0.2, metrics.FalseNegativeRate!.Value, 0.0001);
    }

    [TestMethod]
    public void F1Score_ShouldBeHarmonicMean()
    {
        var metrics = new EvaluationMetrics
        {
            TruePositives = 80,
            TrueNegatives = 90,
            FalsePositives = 10,
            FalseNegatives = 20
        };

        double expected = 2 * (80.0 / 90) * (80.0 / 100) / ((80.0 / 90) + (80.0 / 100));
        Assert.AreEqual(expected, metrics.F1Score!.Value, 0.0001);
    }

    [TestMethod]
    public void ZeroDenominator_ShouldReturnNull()
    {
        var metrics = new EvaluationMetrics();

        Assert.IsNull(metrics.Accuracy);
        Assert.IsNull(metrics.Precision);
        Assert.IsNull(metrics.Recall);
        Assert.IsNull(metrics.F1Score);
        Assert.IsNull(metrics.FalsePositiveRate);
        Assert.IsNull(metrics.FalseNegativeRate);
    }

    [TestMethod]
    public void NoPredictedPositives_ShouldReturnNullPrecision()
    {
        var metrics = new EvaluationMetrics
        {
            TruePositives = 0,
            TrueNegatives = 50,
            FalsePositives = 0,
            FalseNegatives = 10
        };

        Assert.IsNull(metrics.Precision);
        Assert.IsNull(metrics.F1Score);
        Assert.AreEqual(0.0, metrics.Recall!.Value, 0.0001);
    }
}

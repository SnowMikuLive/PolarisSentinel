using System.Text.Json;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Inference;

namespace PolarisSentienlUnitTestProject;

// Compares the C# inference layer with the Python results on the same real features.
[TestClass]
public class OnnxInferenceEngineTests
{
    private static RandomForestModel _randomForest = null!;
    private static IsolationForestModel _isolationForest = null!;
    private static ModelCombinationService _combinations = null!;
    private static OnnxInferenceEngine _engine = null!;
    private static JsonDocument _cases = null!;

    [ClassInitialize]
    public static void Setup(TestContext context)
    {
        string artifacts = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../ml/artifacts"));
        _randomForest = new RandomForestModel(Path.Combine(artifacts, "rf_model.onnx"));
        _isolationForest = new IsolationForestModel(Path.Combine(artifacts, "if_model.onnx"), _randomForest.FeatureNames);
        _combinations = new ModelCombinationService(_randomForest, _isolationForest);
        _engine = new OnnxInferenceEngine(_combinations);
        _cases = JsonDocument.Parse(File.ReadAllText(Path.Combine(artifacts, "inference_cases.json")));
    }

    [ClassCleanup]
    public static void Cleanup()
    {
        _randomForest.Dispose();
        _isolationForest.Dispose();
        _cases.Dispose();
    }

    [TestMethod]
    [DataRow("rf_attack")]
    [DataRow("benign_normal")]
    [DataRow("benign_anomaly")]
    [DataRow("low_rf_normal")]
    [DataRow("low_rf_anomaly")]
    public void Detect_ShouldMatchPythonRouting(string name)
    {
        var sample = _cases.RootElement.GetProperty(name);
        var flow = CreateFlow(sample);

        var result = _engine.Detect(flow, ModelCombination.RandomForestThenIsolation);

        Assert.AreEqual(sample.GetProperty("attackType").GetString(), result.AttackType);
        Assert.AreEqual(sample.GetProperty("source").GetString(), result.DetectionSource.ToString());

        // A benign alert carries no score; only malicious results are scored.
        if (result.AttackType != "Benign")
        {
            // The IF score is calibrated from a float32 ONNX output, so allow the same
            // tolerance the Python export uses when comparing scores (SCORE_DIFF_SANITY).
            double expectedConfidence = sample.GetProperty("confidence").GetDouble();
            Assert.AreEqual(expectedConfidence, result.ConfidenceScore ?? 0, 0.02);
        }

        Assert.AreEqual(flow.SourceIp, result.SourceIp);
        Assert.AreEqual(flow.DestinationPort, result.DestinationPort);
    }

    [TestMethod]
    public void Detect_RandomForestOnly_ShouldNeverReportAnomaly()
    {
        var sample = _cases.RootElement.GetProperty("benign_anomaly");
        var flow = CreateFlow(sample);

        var result = _engine.Detect(flow, ModelCombination.RandomForestOnly);

        Assert.AreNotEqual("Unknown_Anomaly", result.AttackType);
    }

    private static FlowFeatureVector CreateFlow(JsonElement sample) => new()
    {
        Features = sample.GetProperty("features").Deserialize<float[]>()!,
        SourceIp = "203.0.113.66",
        SourcePort = 12345,
        DestinationIp = "192.168.1.10",
        DestinationPort = 80,
        Protocol = 6,
        FlowStartTime = new DateTime(2026, 9, 23),
        FlowEndTime = new DateTime(2026, 9, 23)
    };
}

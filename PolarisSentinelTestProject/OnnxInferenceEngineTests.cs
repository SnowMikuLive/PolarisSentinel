using System.Text.Json;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Inference;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class OnnxInferenceEngineTests
{
    private static OnnxInferenceEngine _dual = null!;
    private static OnnxInferenceEngine _rfOnly = null!;
    private static JsonDocument _cases = null!;

    [ClassInitialize]
    public static void Setup(TestContext context)
    {
        string artifacts = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../ml/artifacts"));
        _dual = new OnnxInferenceEngine(Path.Combine(artifacts, "rf_model.onnx"), Path.Combine(artifacts, "if_model.onnx"));
        _rfOnly = new OnnxInferenceEngine(Path.Combine(artifacts, "rf_model.onnx"));
        _cases = JsonDocument.Parse(File.ReadAllText(Path.Combine(artifacts, "inference_cases.json")));
    }

    [ClassCleanup]
    public static void Cleanup()
    {
        _dual.Dispose();
        _rfOnly.Dispose();
        _cases.Dispose();
    }

    // 用 Python 留下的真实特征检查两个运行时的结果。
    // Compare the C# engine with Python results on the same real features.
    [TestMethod]
    [DataRow("rf_attack")]
    [DataRow("benign_normal")]
    [DataRow("benign_anomaly")]
    [DataRow("low_rf_normal")]
    [DataRow("low_rf_anomaly")]
    public void Detect_ShouldMatchPythonRouting(string name)
    {
        var sample = _cases.RootElement.GetProperty(name);
        var flow = new FlowFeatureVector
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

        var result = _dual.Detect(flow);
        var rfResult = _rfOnly.Detect(flow);

        Assert.AreEqual(sample.GetProperty("attackType").GetString(), result.AttackType);
        Assert.AreEqual(sample.GetProperty("source").GetString(), result.Source.ToString());
        Assert.AreEqual(sample.GetProperty("confidence").GetDouble(), result.Confidence, 0.00001);
        Assert.AreEqual(sample.GetProperty("rfOnlyAttackType").GetString(), rfResult.AttackType);
        Assert.AreEqual(sample.GetProperty("rfOnlySource").GetString(), rfResult.Source.ToString());
        Assert.AreEqual(flow.SourceIp, result.SourceIp);
        Assert.AreEqual(flow.DestinationPort, result.DestinationPort);
    }
}

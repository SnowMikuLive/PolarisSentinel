using System.Globalization;
using System.Text.Json;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Inference;

// Isolation Forest anomaly detector backed by an ONNX model.
public class IsolationForestModel : IIsolationForestModel, IDisposable
{
    private const float MinConfidence = 0.60f;
    private const float MaxConfidence = 0.99f;

    private readonly InferenceSession _session;
    private readonly string _inputName;
    private readonly double _scoreAtAlertConfidence;
    private readonly double _scoreAtHighConfidence;

    public IReadOnlyList<string> FeatureNames { get; }

    private double AnomalyThreshold { get; }

    public IsolationForestModel(string modelPath, IReadOnlyList<string> classifierFeatureNames)
    {
        if (!File.Exists(modelPath))
        {
            throw new FileNotFoundException($"ONNX anomaly detector not found: {modelPath}");
        }

        _session = new InferenceSession(modelPath);
        _inputName = _session.InputMetadata.Keys.First();

        var metadata = _session.ModelMetadata.CustomMetadataMap;
        FeatureNames = JsonSerializer.Deserialize<string[]>(metadata["feature_names"])!;
        if (!FeatureNames.SequenceEqual(classifierFeatureNames))
        {
            throw new InvalidOperationException(
                "Classifier and anomaly detector were exported with different feature schemas.");
        }

        AnomalyThreshold = ParseDouble(metadata["anomaly_threshold"]);
        _scoreAtAlertConfidence = ParseDouble(metadata["score_at_confidence_060"]);
        _scoreAtHighConfidence = ParseDouble(metadata["score_at_confidence_095"]);
    }

    public InferenceResult Score(FlowFeatureVector flow)
    {
        double score = RawScore(flow);

        float confidence = Normalize(score);

        return new InferenceResult
        {
            AttackType = AttackTypes.UnknownAnomaly,
            ConfidenceScore = confidence,
            Description = "Isolation Forest detected an anomalous flow."
        };
    }

    public bool IsAnomaly(FlowFeatureVector flow) => RawScore(flow) < AnomalyThreshold;

    private double RawScore(FlowFeatureVector flow)
    {
        if (flow.Features.Length != FeatureNames.Count)
        {
            throw new ArgumentException($"Expected {FeatureNames.Count} features, got {flow.Features.Length}.");
        }

        var input = new DenseTensor<float>(flow.Features, new int[] { 1, FeatureNames.Count });
        using var results = _session.Run(
            new NamedOnnxValue[] { NamedOnnxValue.CreateFromTensor(_inputName, input) });
        return results.First(r => r.Name == "scores").AsEnumerable<float>().First();
    }

    private float Normalize(double score)
    {
        double span = _scoreAtAlertConfidence - _scoreAtHighConfidence;
        double t = span > 0 ? (_scoreAtAlertConfidence - score) / span : 1.0;
        double confidence = MinConfidence + (0.95f - MinConfidence) * t;
        return (float)Math.Clamp(confidence, MinConfidence, MaxConfidence);
    }

    private static double ParseDouble(string value) => double.Parse(value, CultureInfo.InvariantCulture);

    public void Dispose() => _session.Dispose();
}

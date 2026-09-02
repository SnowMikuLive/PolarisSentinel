using System.Globalization;
using System.Text.Json;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Inference;

public sealed class OnnxInferenceEngine : IInferenceEngine, IDisposable
{
    private readonly InferenceSession _session;
    private readonly string _inputName;

    public IReadOnlyList<string> ClassNames { get; }
    public IReadOnlyList<string> FeatureNames { get; }
    public double RfConfidenceThreshold { get; }
    public double AutoBlockConfidenceThreshold { get; }

    public OnnxInferenceEngine(string modelPath)
    {
        if (!File.Exists(modelPath))
            throw new FileNotFoundException($"ONNX model not found: {modelPath}");

        _session = new InferenceSession(modelPath);
        _inputName = _session.InputMetadata.Keys.First();

        // Schema and thresholds are embedded by ml/scripts/export_onnx.py,
        // so the C# side never hardcodes them.
        var metadata = _session.ModelMetadata.CustomMetadataMap;
        ClassNames = JsonSerializer.Deserialize<string[]>(metadata["class_names"])!;
        FeatureNames = JsonSerializer.Deserialize<string[]>(metadata["feature_names"])!;
        RfConfidenceThreshold = double.Parse(
            metadata["rf_confidence_threshold"], CultureInfo.InvariantCulture);
        AutoBlockConfidenceThreshold = double.Parse(
            metadata["auto_block_confidence_threshold"], CultureInfo.InvariantCulture);
    }

    public DetectionResult Detect(FlowFeatureVector flow)
    {
        if (flow.Features.Length != FeatureNames.Count)
            throw new ArgumentException(
                $"Expected {FeatureNames.Count} features, got {flow.Features.Length}.");

        var input = new DenseTensor<float>(flow.Features, [1, FeatureNames.Count]);
        using var results = _session.Run(
            [NamedOnnxValue.CreateFromTensor(_inputName, input)]);

        var probabilities = results
            .First(r => r.Name == "probabilities")
            .AsTensor<float>();

        int best = 0;
        for (int i = 1; i < ClassNames.Count; i++)
        {
            if (probabilities[0, i] > probabilities[0, best])
                best = i;
        }

        string attackType = ClassNames[best];
        return new DetectionResult
        {
            AttackType = attackType,
            Confidence = probabilities[0, best],
            Source = attackType == AttackTypes.Benign
                ? DetectionSource.None
                : DetectionSource.RandomForest,
            SourceIp = flow.SourceIp,
        };
    }

    public void Dispose() => _session.Dispose();
}

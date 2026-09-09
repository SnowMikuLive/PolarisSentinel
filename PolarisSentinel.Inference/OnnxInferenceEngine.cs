using System.Globalization;
using System.Text.Json;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Inference;

// 并行架构：RF 对每条流全量分类；IF 仅审查被判良性的流以发现未知异常。
// 若在 RF 前加门控，检测上限会被 IF 召回率卡住（实测 PortScan 99.9% → 0.3%）。
// Parallel architecture: RF classifies every flow; IF only scores benign flows for unknown
// anomalies. A gate in front of RF would cap detection at IF recall (PortScan 99.9% → 0.3%).
public sealed class OnnxInferenceEngine : IInferenceEngine, IDisposable
{
    private const double AlertConfidence = 0.60;
    private const double HighConfidence = 0.95;
    private const double MaxConfidence = 0.99;

    private readonly InferenceSession _classifier;
    private readonly string _classifierInput;
    private readonly InferenceSession? _anomalyDetector;
    private readonly string? _anomalyInput;
    private readonly double _scoreAtAlertConfidence;
    private readonly double _scoreAtHighConfidence;

    public IReadOnlyList<string> ClassNames { get; }
    public IReadOnlyList<string> FeatureNames { get; }
    public double RfConfidenceThreshold { get; }
    public double AutoBlockConfidenceThreshold { get; }

    public bool AnomalyDetectionEnabled => _anomalyDetector is not null;
    public double? AnomalyThreshold { get; }

    public OnnxInferenceEngine(string classifierPath, string? anomalyDetectorPath = null)
    {
        if (!File.Exists(classifierPath))
            throw new FileNotFoundException($"ONNX classifier not found: {classifierPath}");

        _classifier = new InferenceSession(classifierPath);
        _classifierInput = _classifier.InputMetadata.Keys.First();

        // 特征 schema 和策略阈值由 ml/scripts/export_onnx.py 写入元数据，C# 端零硬编码
        // Feature schema and policy thresholds are embedded by export_onnx.py; no C# hardcoding
        var metadata = _classifier.ModelMetadata.CustomMetadataMap;
        ClassNames = JsonSerializer.Deserialize<string[]>(metadata["class_names"])!;
        FeatureNames = JsonSerializer.Deserialize<string[]>(metadata["feature_names"])!;
        RfConfidenceThreshold = ParseDouble(metadata["rf_confidence_threshold"]);
        AutoBlockConfidenceThreshold = ParseDouble(metadata["auto_block_confidence_threshold"]);

        // IF 模型路径可选；配置为空时退化为 RF 单模型
        // IF model path is optional; omit to run RF-only without error
        if (anomalyDetectorPath is null)
            return;
        if (!File.Exists(anomalyDetectorPath))
            throw new FileNotFoundException($"ONNX anomaly detector not found: {anomalyDetectorPath}");

        _anomalyDetector = new InferenceSession(anomalyDetectorPath);
        _anomalyInput = _anomalyDetector.InputMetadata.Keys.First();

        var anomalyMetadata = _anomalyDetector.ModelMetadata.CustomMetadataMap;
        var anomalyFeatures = JsonSerializer.Deserialize<string[]>(anomalyMetadata["feature_names"])!;
        if (!anomalyFeatures.SequenceEqual(FeatureNames))
            throw new InvalidOperationException(
                "Classifier and anomaly detector were exported with different feature schemas.");

        AnomalyThreshold = ParseDouble(anomalyMetadata["anomaly_threshold"]);
        _scoreAtAlertConfidence = ParseDouble(anomalyMetadata["score_at_confidence_060"]);
        _scoreAtHighConfidence = ParseDouble(anomalyMetadata["score_at_confidence_095"]);
    }

    public DetectionResult Detect(FlowFeatureVector flow)
    {
        if (flow.Features.Length != FeatureNames.Count)
            throw new ArgumentException(
                $"Expected {FeatureNames.Count} features, got {flow.Features.Length}.");

        var input = new DenseTensor<float>(flow.Features, [1, FeatureNames.Count]);

        using var classified = _classifier.Run(
            [NamedOnnxValue.CreateFromTensor(_classifierInput, input)]);
        var probabilities = classified.First(r => r.Name == "probabilities").AsTensor<float>();

        int best = 0;
        for (int i = 1; i < ClassNames.Count; i++)
        {
            if (probabilities[0, i] > probabilities[0, best])
                best = i;
        }

        string attackType = ClassNames[best];
        if (attackType != AttackTypes.Benign)
        {
            return new DetectionResult
            {
                AttackType = attackType,
                Confidence = probabilities[0, best],
                Source = DetectionSource.RandomForest,
                SourceIp = flow.SourceIp,
            };
        }

        if (_anomalyDetector is not null)
        {
            using var scored = _anomalyDetector.Run(
                [NamedOnnxValue.CreateFromTensor(_anomalyInput!, input)]);
            // "scores" 即 sklearn decision_function；分数越低越异常
            // "scores" is sklearn's decision_function; lower means more anomalous
            double score = scored.First(r => r.Name == "scores").AsEnumerable<float>().First();

            if (score < AnomalyThreshold!.Value)
            {
                return new DetectionResult
                {
                    AttackType = AttackTypes.UnknownAnomaly,
                    Confidence = CalibrateConfidence(score),
                    Source = DetectionSource.IsolationForest,
                    SourceIp = flow.SourceIp,
                };
            }
        }

        return new DetectionResult
        {
            AttackType = AttackTypes.Benign,
            Confidence = probabilities[0, best],
            Source = DetectionSource.None,
            SourceIp = flow.SourceIp,
        };
    }

    // 将原始异常分数映射到与 RF 相同的 [0,1] 置信度尺度，策略引擎可用统一阈值比较。
    // 异常阈值对应 0.60；十倍更罕见的分数对应 0.95。
    // Maps raw anomaly score onto the same [0,1] scale as RF so the policy engine can
    // compare one Confidence field. Threshold lands on 0.60; a ten-times-rarer score on 0.95.
    private float CalibrateConfidence(double score)
    {
        double span = _scoreAtAlertConfidence - _scoreAtHighConfidence;
        double t = span > 0 ? (_scoreAtAlertConfidence - score) / span : 1.0;
        double confidence = AlertConfidence + (HighConfidence - AlertConfidence) * t;
        return (float)Math.Clamp(confidence, AlertConfidence, MaxConfidence);
    }

    private static double ParseDouble(string value) =>
        double.Parse(value, CultureInfo.InvariantCulture);

    public void Dispose()
    {
        _classifier.Dispose();
        _anomalyDetector?.Dispose();
    }
}

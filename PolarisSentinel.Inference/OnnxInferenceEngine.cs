using System.Globalization;
using System.Text.Json;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Inference
{
    //RF分类，IF检查良性流
    //RF classifies traffic; IF checks benign flows
    public class OnnxInferenceEngine : IInferenceEngine, IDisposable
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

        public bool AnomalyDetectionEnabled
        {
            get
            {
                return _anomalyDetector != null;
            }
        }
        public double? AnomalyThreshold { get; }

        public OnnxInferenceEngine(string classifierPath, string? anomalyDetectorPath = null)
        {
            if (!File.Exists(classifierPath))
            {
                throw new FileNotFoundException($"ONNX classifier not found: {classifierPath}");
            }

            _classifier = new InferenceSession(classifierPath);
            _classifierInput = _classifier.InputMetadata.Keys.First();

            //从模型读取特征和阈值
            //Read features and thresholds from the model
            var metadata = _classifier.ModelMetadata.CustomMetadataMap;
            ClassNames = JsonSerializer.Deserialize<string[]>(metadata["class_names"])!;
            FeatureNames = JsonSerializer.Deserialize<string[]>(metadata["feature_names"])!;
            RfConfidenceThreshold = ParseDouble(metadata["rf_confidence_threshold"]);
            AutoBlockConfidenceThreshold = ParseDouble(metadata["auto_block_confidence_threshold"]);

            if (anomalyDetectorPath == null)
            {
                //未提供IF路径时只使用RF
                //Use RF only when no IF path is provided
                return;
            }
            if (!File.Exists(anomalyDetectorPath))
            {
                throw new FileNotFoundException($"ONNX anomaly detector not found: {anomalyDetectorPath}");
            }

            _anomalyDetector = new InferenceSession(anomalyDetectorPath);
            _anomalyInput = _anomalyDetector.InputMetadata.Keys.First();

            var anomalyMetadata = _anomalyDetector.ModelMetadata.CustomMetadataMap;
            var anomalyFeatures = JsonSerializer.Deserialize<string[]>(anomalyMetadata["feature_names"])!;
            if (!anomalyFeatures.SequenceEqual(FeatureNames))
            {
                throw new InvalidOperationException(
                    "Classifier and anomaly detector were exported with different feature schemas.");
            }

            AnomalyThreshold = ParseDouble(anomalyMetadata["anomaly_threshold"]);
            _scoreAtAlertConfidence = ParseDouble(anomalyMetadata["score_at_confidence_060"]);
            _scoreAtHighConfidence = ParseDouble(anomalyMetadata["score_at_confidence_095"]);
        }

        public Alert Detect(FlowFeatureVector flow)
        {
            if (flow.Features.Length != FeatureNames.Count)
            {
                throw new ArgumentException(
                    $"Expected {FeatureNames.Count} features, got {flow.Features.Length}.");
            }

            var input = new DenseTensor<float>(flow.Features, new int[] { 1, FeatureNames.Count });

            using var classified = _classifier.Run(
                new NamedOnnxValue[] { NamedOnnxValue.CreateFromTensor(_classifierInput, input) });
            var probabilities = classified.First(r => r.Name == "probabilities").AsTensor<float>();

            int best = 0;
            for (int i = 1; i < ClassNames.Count; i++)
            {
                if (probabilities[0, i] > probabilities[0, best])
                {
                    best = i;
                }
            }

            string attackType = ClassNames[best];
            if (attackType != AttackTypes.Benign)
            {
                return CreateAlert(flow, attackType, probabilities[0, best], DetectionSource.RandomForest);
            }

            if (_anomalyDetector != null)
            {
                using var scored = _anomalyDetector.Run(
                    new NamedOnnxValue[] { NamedOnnxValue.CreateFromTensor(_anomalyInput!, input) });
                //decision_function分数越低越异常
                //Lower decision_function scores mean more anomalous traffic
                double score = scored.First(r => r.Name == "scores").AsEnumerable<float>().First();

                if (score < AnomalyThreshold!.Value)
                {
                    return CreateAlert(flow, AttackTypes.UnknownAnomaly, CalibrateConfidence(score), DetectionSource.IsolationForest);
                }
            }

            return CreateAlert(flow, AttackTypes.Benign, probabilities[0, best], DetectionSource.None);
        }

        //推理只填充检测字段；Id /决策字段由调用方补全
        //Inference fills detection fields only; Id / decision fields are set by the caller
        private static Alert CreateAlert(FlowFeatureVector flow, string attackType, float confidence, DetectionSource source)
        {
            return new Alert
            {
                AttackType = attackType,
                Confidence = confidence,
                Source = source,
                SourceIp = flow.SourceIp,
                DestinationIp = flow.DestinationIp,
                SourcePort = flow.SourcePort,
                DestinationPort = flow.DestinationPort,
                Protocol = flow.Protocol,
                Reason = string.Empty
            };
        }

        //用模型中的两个分数点计算置信度
        //Calculate confidence using the two score points from the model
        private float CalibrateConfidence(double score)
        {
            double span = _scoreAtAlertConfidence - _scoreAtHighConfidence;
            double t = span > 0 ? (_scoreAtAlertConfidence - score) / span : 1.0;
            double confidence = AlertConfidence + (HighConfidence - AlertConfidence) * t;
            return (float)Math.Clamp(confidence, AlertConfidence, MaxConfidence);
        }

        private static double ParseDouble(string value)
        {
            return double.Parse(value, CultureInfo.InvariantCulture);
        }

        public void Dispose()
        {
            _classifier.Dispose();
            _anomalyDetector?.Dispose();
        }
    }
}

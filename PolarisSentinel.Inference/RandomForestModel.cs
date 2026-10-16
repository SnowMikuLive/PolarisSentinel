using System.Globalization;
using System.Text.Json;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Inference;

public class RandomForestModel : IRandomForestModel, IDisposable
{
    private readonly InferenceSession _session;
    private readonly string _inputName;
    private readonly int _benignIndex;

    private IReadOnlyList<string> ClassNames { get; }

    public IReadOnlyList<string> FeatureNames { get; }

    private const double MaxConfidenceThreshold = 0.50;

    private double ConfidenceThreshold { get; }

    public RandomForestModel(string modelPath)
    {
        if (!File.Exists(modelPath))
        {
            throw new FileNotFoundException($"ONNX classifier not found: {modelPath}");
        }

        _session = new InferenceSession(modelPath);
        _inputName = _session.InputMetadata.Keys.First();

        var metadata = _session.ModelMetadata.CustomMetadataMap;
        ClassNames = JsonSerializer.Deserialize<string[]>(metadata["class_names"])!;
        FeatureNames = JsonSerializer.Deserialize<string[]>(metadata["feature_names"])!;
        ConfidenceThreshold = Math.Min(ParseDouble(metadata["rf_confidence_threshold"]), MaxConfidenceThreshold);
        _benignIndex = Array.IndexOf(ClassNames.ToArray(), AttackTypes.Benign);
    }

    public InferenceResult Classify(FlowFeatureVector flow)
    {
        var probabilities = Run(flow);

        int best = 0;
        for (int i = 1; i < ClassNames.Count; i++)
        {
            if (probabilities[i] > probabilities[best])
            {
                best = i;
            }
        }

        float probability = probabilities[best];
        string label = ClassNames[best];

        if (label == AttackTypes.Benign)
        {
            return new InferenceResult { AttackType = AttackTypes.Benign, ConfidenceScore = probability };
        }

        if (!AttackTypes.TryParse(label, out string known))
        {
            throw new InvalidOperationException(
                $"Model emitted unknown class '{label}'. Expected one of: {string.Join(", ", AttackTypes.All)}.");
        }

        return new InferenceResult
        {
            AttackType = known,
            ConfidenceScore = probability,
            Description = $"Random Forest classified the flow as {known}."
        };
    }

    public bool ExceedsThreshold(InferenceResult result) =>
        result.AttackType != AttackTypes.Benign && result.ConfidenceScore >= ConfidenceThreshold;

    public float BenignProbability(FlowFeatureVector flow) => Run(flow)[_benignIndex];

    /// <summary>
    /// Runs the classifier and returns a managed copy of the probabilities. The ONNX output
    /// tensor is a view over native memory that is released when the results are disposed, so it
    /// must be copied before this method returns.
    /// </summary>
    private float[] Run(FlowFeatureVector flow)
    {
        if (flow.Features.Length != FeatureNames.Count)
        {
            throw new ArgumentException($"Expected {FeatureNames.Count} features, got {flow.Features.Length}.");
        }

        var input = new DenseTensor<float>(flow.Features, new int[] { 1, FeatureNames.Count });
        using var results = _session.Run(
            new NamedOnnxValue[] { NamedOnnxValue.CreateFromTensor(_inputName, input) });
        return results.First(r => r.Name == "probabilities").AsTensor<float>().ToArray();
    }

    private static double ParseDouble(string value) => double.Parse(value, CultureInfo.InvariantCulture);

    public void Dispose() => _session.Dispose();
}

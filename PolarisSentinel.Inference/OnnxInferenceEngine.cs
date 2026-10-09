using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Inference;

// Adapts the model combination service to the alert shape used by the detection pipeline.
public class OnnxInferenceEngine : IInferenceEngine
{
    private readonly IModelCombinationService _combinations;

    public OnnxInferenceEngine(IModelCombinationService combinations)
    {
        _combinations = combinations;
    }

    public Alert Detect(FlowFeatureVector flow) => Detect(flow, _combinations.ActiveCombination);

    public Alert Detect(FlowFeatureVector flow, ModelCombination combination)
    {
        var result = _combinations.Run(flow, combination);

        return new Alert
        {
            DetectionSource = SourceFor(result),
            AttackType = result.AttackType,
            ConfidenceScore = result.AttackType == AttackTypes.Benign ? null : result.ConfidenceScore,
            Description = result.Description,
            SourceIp = flow.SourceIp,
            SourcePort = flow.SourcePort,
            DestinationIp = flow.DestinationIp,
            DestinationPort = flow.DestinationPort,
            Protocol = flow.Protocol,
            SynCount = flow.SynCount,
            AckCount = flow.AckCount,
            FinCount = flow.FinCount,
            RstCount = flow.RstCount,
            PshCount = flow.PshCount,
            CreatedAt = flow.FlowEndTime
        };
    }

    private static DetectionSource SourceFor(InferenceResult result)
    {
        if (result.AttackType == AttackTypes.Benign)
        {
            return DetectionSource.None;
        }

        return result.AttackType == AttackTypes.UnknownAnomaly
            ? DetectionSource.IsolationForest
            : DetectionSource.RandomForest;
    }
}

using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Application;

// Application use case: run one completed flow through the detection pipeline using the
// currently enabled policies. Presentation layers call this instead of orchestrating the
// pipeline, repositories, and policy lookup themselves.
public class FlowProcessingService
{
    private readonly IDetectionPipeline _pipeline;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<FlowProcessingService> _logger;

    public FlowProcessingService(
        IDetectionPipeline pipeline,
        IUnitOfWork unitOfWork,
        ILogger<FlowProcessingService> logger)
    {
        _pipeline = pipeline;
        _unitOfWork = unitOfWork;
        _logger = logger;
    }

    // Returns the outcome for the flow, or null when processing failed.
    public async Task<DetectionOutcome?> ProcessAsync(FlowFeatureVector flow, CancellationToken cancellationToken = default)
    {
        try
        {
            var policies = await _unitOfWork.Policies.GetEnabledAsync(cancellationToken);
            return _pipeline.ProcessFlow(flow, policies);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Pipeline failed for flow from {SourceIp}", flow.SourceIp);
            return null;
        }
    }
}

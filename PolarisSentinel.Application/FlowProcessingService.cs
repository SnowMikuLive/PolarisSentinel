using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Application;

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

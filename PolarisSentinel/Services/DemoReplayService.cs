using System.Text.Json;
using Microsoft.AspNetCore.SignalR;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Hubs;
using PolarisSentinel.Inference;

namespace PolarisSentinel.Services;

//Feeds pre-sampled CIC-IDS2017 test flows through the real inference engine
//so the dashboard can be demonstrated without live capture or attack tooling.
public sealed class DemoReplayService : BackgroundService
{
    private sealed record DemoFlow(
        float[] Features,
        string SourceIp,
        ushort SourcePort,
        string DestinationIp,
        ushort DestinationPort,
        byte Protocol,
        string TrueLabel);

    private readonly OnnxInferenceEngine _engine;
    private readonly IHubContext<DetectionHub> _hub;
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<DemoReplayService> _logger;
    private readonly int _intervalMs;

    public DemoReplayService(
        OnnxInferenceEngine engine,
        IHubContext<DetectionHub> hub,
        IWebHostEnvironment environment,
        IConfiguration configuration,
        ILogger<DemoReplayService> logger)
    {
        _engine = engine;
        _hub = hub;
        _environment = environment;
        _logger = logger;
        _intervalMs = configuration.GetValue("Demo:IntervalMs", 400);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string path = Path.Combine(_environment.ContentRootPath, "DemoData", "demo_flows.json");
        var flows = JsonSerializer.Deserialize<List<DemoFlow>>(
            await File.ReadAllTextAsync(path, stoppingToken),
            new JsonSerializerOptions(JsonSerializerDefaults.Web))!;

        _logger.LogInformation(
            "Demo replay started: {Count} flows, one every {Interval} ms", flows.Count, _intervalMs);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                foreach (var flow in flows)
                {
                    var now = DateTime.UtcNow;
                    var detection = _engine.Detect(new FlowFeatureVector
                    {
                        Features = flow.Features,
                        SourceIp = flow.SourceIp,
                        SourcePort = flow.SourcePort,
                        DestinationIp = flow.DestinationIp,
                        DestinationPort = flow.DestinationPort,
                        Protocol = flow.Protocol,
                        FlowStartTime = now,
                        FlowEndTime = now,
                    });

                    string tier =
                        detection.AttackType == AttackTypes.Benign ? "benign"
                        : detection.Confidence >= _engine.AutoBlockConfidenceThreshold ? "block"
                        : detection.Confidence >= _engine.RfConfidenceThreshold ? "alert"
                        : "low";

                    await _hub.Clients.All.SendAsync("detection", new
                    {
                        time = DateTime.Now.ToString("HH:mm:ss"),
                        sourceIp = detection.SourceIp,
                        destinationPort = flow.DestinationPort,
                        attackType = detection.AttackType,
                        confidence = detection.Confidence,
                        tier,
                    }, stoppingToken);

                    await Task.Delay(_intervalMs, stoppingToken);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // normal shutdown
        }
    }
}

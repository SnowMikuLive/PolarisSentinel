using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Options;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Web.Hubs;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace PolarisSentinel.Web.Service
{
    //抓包事件适配器：调用检测管线、推送SignalR、持久化结果
    //Capture adapter:runs detection pipeline,pushes SignalR,persists results
    public class TrafficBroadcastService:IHostedService, IDisposable
    {
        private readonly IHubContext<TrafficHub> _hubContext;
        private readonly ITrafficCaptureService _trafficCaptureService;
        private readonly IDetectionPipeline _pipeline;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly CaptureControlService _captureControl;
        private readonly ILogger<TrafficBroadcastService> _logger;
        private readonly IOptionsMonitor<UserSettings> _policySettings;

        private readonly DetectionStateService _state;

        public TrafficBroadcastService(
            IHubContext<TrafficHub> hubContext, 
            ITrafficCaptureService trafficCaptureService,
            IDetectionPipeline pipeline,
            IServiceScopeFactory scopeFactory,
            CaptureControlService captureControl,
            DetectionStateService state,
            IOptionsMonitor<UserSettings> policySettings,
            ILogger<TrafficBroadcastService> logger
            )
        {
            _hubContext = hubContext;
            _trafficCaptureService = trafficCaptureService;
            _pipeline = pipeline;
            _scopeFactory = scopeFactory;
            _captureControl = captureControl;
            _state = state;
            _policySettings = policySettings;
            _logger = logger;
        }

        //Subscribe to event when service starts
        public Task StartAsync(CancellationToken cancellationToken)
        {
            //modify: Subscribe first, then start the traffic capture service to avoid missing any events
            // Subscribe to the OnLiveTrafficSummary event
            _trafficCaptureService.OnLiveTrafficSummary += OnLiveTrafficSummaryHandler;

            //Subscribe to flow completion event for real inference and policy evaluation
            _trafficCaptureService.OnFlowCompleted += OnFlowCompletedHandler;

            //Auto-select a device (Wi-Fi preferred) and start capture.
            try
            {
                _captureControl.AutoStart();
            }
            catch (Exception ex)
            {
                // Log the exception to the debug output
                _logger.LogError(ex, "Failed to start traffic capture");
            }
                return Task.CompletedTask;
        }

        //Handle live traffic summery event
        private async void OnLiveTrafficSummaryHandler(object? sender, LiveTrafficSummary summary)
        {
            try
            {
                await _hubContext.Clients.All.SendAsync("ReceiveLiveTrafficSummary", summary);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to boardcast live traffic summary:{ex.Message}");
            }
        }

        private async void OnFlowCompletedHandler(object? sender, FlowFeatureVector flow)
        {
            try
            {
                // Capture features already match the model contract; keep the flow addresses and times.
                var modelFlow = new FlowFeatureVector
                {
                    Features = flow.Features,
                    SourceIp = flow.SourceIp,
                    SourcePort = flow.SourcePort,
                    DestinationIp = flow.DestinationIp,
                    DestinationPort = flow.DestinationPort,
                    Protocol = flow.Protocol,
                    FlowStartTime = flow.FlowStartTime,
                    FlowEndTime = flow.FlowEndTime,
                    TotalPackets = flow.TotalPackets,
                    TotalBytes = flow.TotalBytes,
                    PreFilterVerdict = flow.PreFilterVerdict
                };
                var decision = _pipeline.ProcessFlow(modelFlow);
                _logger.LogInformation(
                    "Flow {SourceIp}: {InputCount}->20 features, {AttackType}, {Source}, {Action}, {Reason}",
                    decision.SourceIp, flow.Features.Length, decision.AttackType,
                    decision.Source, decision.Action, decision.Reason);

                var record = new DetectionRecord(
                    decision.Id,
                    decision.SourceIp,
                    flow.DestinationIp,
                    flow.DestinationPort,
                    decision.AttackType,
                    decision.Confidence,
                    decision.Action.ToString(),
                    // Background service has no request context; stamp the local system time.
                    SettingsService.Format(decision.DecidedAt),
                    decision.Reason,
                    decision.Source.ToString(),
                    decision.RuleName);

                //先推送结果，写库失败不影响实时页面
                //Push results first so a database error does not stop live updates
                _state.Record(record);
                await _hubContext.Clients.All.SendAsync("ReceivePolicyDecision", record);

                //Persist the alert (5-tuple + inference result) in a short-lived scope,
                //because the unit of work depends on a scoped DbContext while this is a singleton.
                try
                {
                    await using (var scope = _scopeFactory.CreateAsyncScope())
                    {
                        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
                        unitOfWork.Alerts.Add(decision);

                        // 先提交告警，保证 Rule.AlertId 的外键父行已存在
                        // Commit the alert first so the Rule.AlertId FK parent exists
                        await unitOfWork.SaveChangesAsync();

                        //审计：Block决策产生防火墙规则时记录一条Rule
                        //Audit:record a Rule row when a Block creates a firewall rule
                        if (decision.Action == PolicyAction.Block && !string.IsNullOrEmpty(decision.RuleName))
                        {
                            unitOfWork.Rules.Add(new Rule
                            {
                                Id = EntityIds.Rule(await NextRuleNumberAsync(unitOfWork)),
                                Name = decision.RuleName,
                                PolicyId = null,
                                AlertId = decision.Id,
                                Action = decision.Action,
                                RemoteAddress = decision.SourceIp,
                                Enabled = true,
                                AttackType = decision.AttackType,
                                CreatedAt = decision.DecidedAt,
                                ExpiresAt = decision.DecidedAt.AddMinutes(_policySettings.CurrentValue.BlockDurationMinutes)
                            });

                            await unitOfWork.SaveChangesAsync();
                        }
                    }
                }

                catch (Exception ex)
                {
                    _logger.LogError(ex, "Cannot save detection {AlertId}", decision.Id);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Pipeline failed for flow from {SourceIp}", flow.SourceIp);
            }
        }

        //生成下一个R-n审计编号
        //Build the next "R-n" audit number
        private static async Task<int> NextRuleNumberAsync(IUnitOfWork unitOfWork)
        {
            var rules = await unitOfWork.Rules.GetAllAsync();
            int max = 0;
            foreach (var r in rules)
            {
                if (r.Id.StartsWith(EntityIds.RulePrefix, StringComparison.Ordinal) &&
                    int.TryParse(r.Id.AsSpan(EntityIds.RulePrefix.Length), out int n) && n > max)
                {
                    max = n;
                }
            }
            return max + 1;
        }
        
        public Task StopAsync(CancellationToken cancellationToken)
        {
            // Unsubscribe from the OnLiveTrafficSummary event
            _trafficCaptureService.OnLiveTrafficSummary -= OnLiveTrafficSummaryHandler;

            //add: Unsubscribe from flow completionevent
            _trafficCaptureService.OnFlowCompleted -= OnFlowCompletedHandler;

            //add stop traffic capture service
            _trafficCaptureService.Stop();

            return Task.CompletedTask;
        }
        public void Dispose()
        {
            StopAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
    }
}

using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Inference;
using PolarisSentinel.TrafficCapture;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PolarisSentinel.DataAccess.Data;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PolarisSentinel.Web.Hubs;
using PolarisSentinel.Web.Service;
using PolarisSentinel.PolicyDecision;
using PolarisSentinel.FirewallEnforement;
using PolarisSentinel.Application;
using Microsoft.Extensions.Hosting.WindowsServices;
using PolarisSentinel.DataAccess.Repository;
namespace PolarisSentinel
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            //builder.Service
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddControllersWithViews();

            //Add SignalR with camelCase JSON so frontend JS can read properties directly
            builder.Services.AddSignalR()
                .AddJsonProtocol(options =>
                {
                    options.PayloadSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
                });

<<<<<<< HEAD
            //策略配置热重载
            //Policy settings hot-reload
            builder.Services.Configure<Policy>(
=======
            // 策略配置热重载（默认值来自 appsettings）
            // Policy settings (defaults from appsettings)
            builder.Services.Configure<UserSettings>(
>>>>>>> d47e7ec0c32803f010bc8a3c97a4dc42d392cd92
                builder.Configuration.GetSection("PolicySettings"));
            //防火墙配置（DryRun、封禁时长等）
            //Firewall settings (DryRun,block duration,etc.)
            builder.Services.Configure<FirewallOptions>(
                builder.Configuration.GetSection("Firewall"));

            //Register the ITrafficCaptureService as a singleton service
            //sp is the service provider that allows you to resolve other services from the DI container. In this case, we are resolving IConfiguration to read the configuration values for the TrafficCaptureService.
            builder.Services.AddSingleton<ITrafficCaptureService>(sp =>
            {

                var config = sp.GetRequiredService<IConfiguration>();
                var section = config.GetSection("PolicySettings");
<<<<<<< HEAD
                var settings = sp.GetRequiredService<IOptionsMonitor<Policy>>().CurrentValue;
                //毫秒→秒
                //ms to seconds
=======
                var settings = sp.GetRequiredService<IOptionsMonitor<UserSettings>>().CurrentValue;
                // 毫秒→秒
                // ms to seconds
>>>>>>> d47e7ec0c32803f010bc8a3c97a4dc42d392cd92
                int flowIdleTimeoutSeconds = settings.FlowIdleTimeoutMilliseconds / 1000;
                int preFilterMinPackets = settings.PreFilterMinPackets;

                // Use the null-coalescing operator to provide a default value of 5 if LiveSummaryIntervalSeconds is not set in the configuration
                int liveSummaryIntervalSeconds = section.GetValue<int?>("LiveSummaryIntervalSeconds") ?? 5;

                //return a concrete TrafficCaptureService instance
                return new TrafficCaptureService(flowIdleTimeoutSeconds, preFilterMinPackets, liveSummaryIntervalSeconds);
            });

            //先清理遗留规则，再启动抓包
            //Clean up old rules before capture starts
            builder.Services.AddHostedService<FirewallRuleSweeper>();

            //add the registe background broadcast service
            builder.Services.AddHostedService<TrafficBroadcastService>();

            builder.Host.UseWindowsService();

            //Tray icon only in desktop mode, not when running as a Windows service.
            if (!WindowsServiceHelpers.IsWindowsService())
            {
                builder.Services.AddHostedService<TrayIconService>();
            }

            builder.Services.AddDbContext<SentinelDbContext>(options =>
            options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

            //检测审计数据库上下文
            //Detection/audit persistence context
            builder.Services.AddDbContext<SentinelDbContext>(options =>
            options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
            builder.Services.AddDefaultIdentity<IdentityUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = false;
                options.Password.RequiredLength = 6;
            })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<SentinelDbContext>();
<<<<<<< HEAD

            //初始管理员账号配置（密码来自user-secrets /环境变量，不硬编码）
            //Initial admin account configuration (password from user-secrets / env var)
            builder.Services.Configure<AdminSeedOptions>(
                builder.Configuration.GetSection(AdminSeedOptions.SectionName));

            //数据库迁移+初始管理员创建
            //Migrations + initial admin provisioning
=======
            //   dotnet user-secrets set "AdminSeed:Password" "..." --project PolarisSentinel.Web
            // 初始管理员账号配置（密码来自 user-secrets / 环境变量，不硬编码）
            // Initial admin account configuration (password from user-secrets / env var)
            builder.Services.Configure<AdminSeedOptions>(
                builder.Configuration.GetSection(AdminSeedOptions.SectionName));

>>>>>>> d47e7ec0c32803f010bc8a3c97a4dc42d392cd92
            builder.Services.AddScoped<SentinelDbInitializer>();

            //Configure Login path and Access Denied path for the application cookie
            builder.Services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = "/Account/Login";
                options.AccessDeniedPath = "/Account/AccessDenied";
            });

<<<<<<< HEAD
            //检测状态服务（累计计数+最近决策）
            //Detection state service (counters and recent decisions)
=======

>>>>>>> d47e7ec0c32803f010bc8a3c97a4dc42d392cd92
            builder.Services.AddSingleton<DetectionStateService>();


            builder.Services.AddSingleton<CaptureControlService>();

            // 每用户设置（时区 + 阈值 + 防火墙），默认值来自 appsettings
            // Per-user settings (thresholds + firewall); defaults from appsettings
            builder.Services.AddHttpContextAccessor();
            builder.Services.AddSingleton<SettingsService>();

            //RF+IF双模型
            //Dual-model inference
            string modelPath = Path.GetFullPath(Path.Combine(
                builder.Environment.ContentRootPath,
                builder.Configuration["Inference:ModelPath"] ?? "../ml/artifacts/rf_model.onnx"));
            string? anomalyModelPath = builder.Configuration["Inference:AnomalyModelPath"] is { } configured
                ? Path.GetFullPath(Path.Combine(builder.Environment.ContentRootPath, configured))
                : null;
            builder.Services.AddSingleton(_ => new OnnxInferenceEngine(modelPath, anomalyModelPath));
            builder.Services.AddSingleton<IInferenceEngine>(
                sp => sp.GetRequiredService<OnnxInferenceEngine>());

            //冷却计时
            //Cooldown timing
            builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);

            //策略引擎通过Func读取最新配置，支持热重载
            //Policy engine reads latest settings via Func for hot-reload
            builder.Services.AddSingleton<IPolicyEngine>(sp =>
            {
                var monitor = sp.GetRequiredService<IOptionsMonitor<UserSettings>>();
                return new PolicyEngine(
                    () => monitor.CurrentValue,
                    sp.GetRequiredService<TimeProvider>(),
                    sp.GetRequiredService<ILogger<PolicyEngine>>());
            });

            //防火墙执行器
            //Firewall enforcer
            builder.Services.AddSingleton<IFirewallEnforcer, WindowsFirewallEnforcer>();

<<<<<<< HEAD
            //检测管线（推理→策略→封禁）
            //Detection pipeline (inference → policy → enforcement)
=======
            // Detection pipeline (inference -> policy -> enforcement), Application layer.
>>>>>>> d47e7ec0c32803f010bc8a3c97a4dc42d392cd92
            builder.Services.AddSingleton<IDetectionPipeline>(sp =>
            {
                var monitor = sp.GetRequiredService<IOptionsMonitor<UserSettings>>();
                int blockMinutes = monitor.CurrentValue.BlockDurationMinutes;
                return new DetectionPipeline(
                    sp.GetRequiredService<IInferenceEngine>(),
                    sp.GetRequiredService<IPolicyEngine>(),
                    sp.GetRequiredService<IFirewallEnforcer>(),
                    blockMinutes,
                    sp.GetRequiredService<ILogger<DetectionPipeline>>());
            });

            // Detection persistence (single transaction boundary over SentinelDbContext)
            builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();
            builder.Services.AddScoped<IAlertRepository>(sp => sp.GetRequiredService<IUnitOfWork>().Alerts);

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.MapStaticAssets();

            //Web API控制器（含防火墙接口）
            //Web API controllers (includes firewall endpoints)
            app.MapControllers();
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Dashboard}/{action=Index}/{id?}")
                .WithStaticAssets();
            app.MapHub<TrafficHub>("/trafficHub");

            //检测状态API，页面加载时拉取
            //Detection state API for page load
            app.MapGet("/api/detections/state", (DetectionStateService state)=>Results.Json(state.GetSnapshot()))
                .RequireAuthorization();

            app.MapGet("/api/demo/info", (OnnxInferenceEngine engine) => Results.Json(new
            {
                classes = engine.ClassNames,
                featureCount = engine.FeatureNames.Count,
                rfThreshold = engine.RfConfidenceThreshold,
                blockThreshold = engine.AutoBlockConfidenceThreshold,
                anomalyDetection = engine.AnomalyDetectionEnabled,
                anomalyThreshold = engine.AnomalyThreshold,
            }));

<<<<<<< HEAD
            //应用迁移并创建初始管理员（逻辑在SentinelDbInitializer中）
            //Apply migrations and provision the initial admin (logic lives in SentinelDbInitializer)
            using (var scope = app.Services.CreateScope())
=======
            // 应用迁移并创建初始管理员（逻辑在 SentinelDbInitializer 中）
            // Apply migrations and provision the initial admin (logic lives in SentinelDbInitializer)
            await using (var scope = app.Services.CreateAsyncScope())
>>>>>>> d47e7ec0c32803f010bc8a3c97a4dc42d392cd92
            {
                try
                {
                    var initializer = scope.ServiceProvider.GetRequiredService<SentinelDbInitializer>();
                    await initializer.InitializeAsync();

                    // 用已有告警初始化 ID 计数器，避免重启后主键冲突
                    // Seed the alert id counter from existing alerts to avoid PK collisions after restart
                    var uow = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
                    var alerts = await uow.Alerts.GetAllAsync();
                    int maxAlert = 0;
                    foreach (var alert in alerts)
                    {
                        int dash = alert.Id.LastIndexOf('-');
                        if (dash >= 0 && int.TryParse(alert.Id.AsSpan(dash + 1), out int n) && n > maxAlert)
                        {
                            maxAlert = n;
                        }
                    }
                    scope.ServiceProvider.GetRequiredService<IPolicyEngine>().InitializeAlertCounter(maxAlert);
                }
                catch (Exception ex)
                {
                    app.Logger.LogError(ex,
                        "Database initialisation failed; check the connection and migrations.");
                }
            }

            //Run the application
            app.Run();
        }
    }
}

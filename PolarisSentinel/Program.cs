using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Inference;
using PolarisSentinel.TrafficCapture;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Web.Data;
using Microsoft.Extensions.DependencyInjection; 
using Microsoft.Extensions.Options;
using PolarisSentinel.Web.Hubs;
using PolarisSentinel.Web.Service;
using PolarisSentinel.PolicyDecision;
using PolarisSentinel.FirewallEnforement;
using PolarisSentinel.Application;
using PolarisSentinel.Data;
using Microsoft.Extensions.Hosting.WindowsServices;

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

            // 策略配置热重载
            // Policy settings hot-reload
            builder.Services.Configure<PolicySettings>(
                builder.Configuration.GetSection("PolicySettings"));
            // 防火墙配置（DryRun、封禁时长等）
            // Firewall settings (DryRun, block duration, etc.)
            builder.Services.Configure<FirewallOptions>(
                builder.Configuration.GetSection("Firewall"));

            //Register the ITrafficCaptureService as a singleton service
            //sp is the service provider that allows you to resolve other services from the DI container. In this case, we are resolving IConfiguration to read the configuration values for the TrafficCaptureService.
            builder.Services.AddSingleton<ITrafficCaptureService>(sp =>
            {

                var config = sp.GetRequiredService<IConfiguration>();
                var section = config.GetSection("PolicySettings");
                var settings = sp.GetRequiredService<IOptionsMonitor<PolicySettings>>().CurrentValue;
                // 毫秒→秒
                // ms to seconds
                int flowIdleTimeoutSeconds = settings.FlowIdleTimeoutMilliseconds / 1000;
                int preFilterMinPackets = settings.PreFilterMinPackets;

                // Use the null-coalescing operator to provide a default value of 5 if LiveSummaryIntervalSeconds is not set in the configuration
                int liveSummaryIntervalSeconds = section.GetValue<int?>("LiveSummaryIntervalSeconds") ?? 5;

                //return a concrete TrafficCaptureService instance
                return new TrafficCaptureService(flowIdleTimeoutSeconds, preFilterMinPackets, liveSummaryIntervalSeconds);
            });

            // 先清理遗留规则，再启动抓包
            // Clean up old rules before capture starts
            builder.Services.AddHostedService<FirewallRuleSweeper>();

            //add the registe background broadcast service
            builder.Services.AddHostedService<TrafficBroadcastService>();

            builder.Host.UseWindowsService();

            //Tray icon only in desktop mode, not when running as a Windows service.
            if (!WindowsServiceHelpers.IsWindowsService())
            {
                builder.Services.AddHostedService<TrayIconService>();
            }

            builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

            // 检测审计数据库上下文
            // Detection/audit persistence context
            builder.Services.AddDbContext<SentinelDbContext>(options =>
            options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

            //Add DbContext service
            builder.Services.AddDefaultIdentity<IdentityUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = false;
                options.Password.RequiredLength = 6;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();

            //Configure Login path and Access Denied path for the application cookie
            builder.Services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = "/Account/Login";
                options.AccessDeniedPath = "/Account/AccessDenied";
            });

            // 检测状态服务（累计计数 + 最近决策）
            // Detection state service (counters and recent decisions)
            builder.Services.AddSingleton<DetectionStateService>();

            //Capture device control (list + switch)
            builder.Services.AddSingleton<CaptureControlService>();





            // RF+IF 双模型
            // Dual-model inference
            string modelPath = Path.GetFullPath(Path.Combine(
                builder.Environment.ContentRootPath,
                builder.Configuration["Inference:ModelPath"] ?? "../ml/artifacts/rf_model.onnx"));
            string? anomalyModelPath = builder.Configuration["Inference:AnomalyModelPath"] is { } configured
                ? Path.GetFullPath(Path.Combine(builder.Environment.ContentRootPath, configured))
                : null;
            builder.Services.AddSingleton(_ => new OnnxInferenceEngine(modelPath, anomalyModelPath));
            builder.Services.AddSingleton<IInferenceEngine>(
                sp => sp.GetRequiredService<OnnxInferenceEngine>());

            // 冷却计时
            // Cooldown timing
            builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);

            // 策略引擎通过 Func 读取最新配置，支持热重载
            // Policy engine reads latest settings via Func for hot-reload
            builder.Services.AddSingleton<IPolicyEngine>(sp =>
            {
                var monitor = sp.GetRequiredService<IOptionsMonitor<PolicySettings>>();
                return new PolicyEngine(
                    () => monitor.CurrentValue,
                    sp.GetRequiredService<TimeProvider>(),
                    sp.GetRequiredService<ILogger<PolicyEngine>>());
            });

            // 防火墙执行器
            // Firewall enforcer
            builder.Services.AddSingleton<IFirewallEnforcer, WindowsFirewallEnforcer>();

            // 检测管线（推理 → 策略 → 封禁）
            // Detection pipeline (inference → policy → enforcement)
            builder.Services.AddSingleton<IDetectionPipeline>(sp =>
            {
                var monitor = sp.GetRequiredService<IOptionsMonitor<PolicySettings>>();
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

            // Web API 控制器（含防火墙接口）
            // Web API controllers (includes firewall endpoints)
            app.MapControllers();
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}")
                .WithStaticAssets();
            app.MapHub<TrafficHub>("/trafficHub");

            // 检测状态 API，页面加载时拉取
            // Detection state API for page load
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

            //Default Admin User Create
            //Apply pending migrations, then create the default admin user.
            using (var scope = app.Services.CreateScope())
            {
                try
                {
                    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                    await db.Database.MigrateAsync();

                    // 建立检测记录表
                    // Create the detection records table
                    var sentinelDb = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
                    await sentinelDb.Database.MigrateAsync();

                    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
                    var admin = await userManager.FindByNameAsync("admin");

                    //The default admin would not created again when admin not null.
                    if (admin == null)
                    {
                        admin = new IdentityUser
                        {
                            UserName = "admin",
                            Email = "admin@polaris.local",
                            EmailConfirmed = true
                        };

                        // Create the admin user with a default password
                        var result = await userManager.CreateAsync(admin, "Polaris@2026");
                        if (!result.Succeeded)
                        {
                            foreach (var error in result.Errors)
                            {
                                app.Logger.LogError("Failed to create admin user: {Error}", error.Description);
                            }
                        }
                    }
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

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

            // Firewall configuration (DryRun, sweep interval).
            builder.Services.Configure<FirewallOptions>(
                builder.Configuration.GetSection("Firewall"));

            // Traffic capture runs on machine-wide defaults; per-user tuning is applied by the pipeline.
            builder.Services.AddSingleton<ITrafficCaptureService>(sp =>
            {
                var config = sp.GetRequiredService<IConfiguration>();
                var section = config.GetSection("PolicySettings");

                int flowIdleTimeoutSeconds = (section.GetValue<int?>("FlowIdleTimeoutMilliseconds") ?? 120000) / 1000;
                int preFilterMinPackets = section.GetValue<int?>("PreFilterMinPackets") ?? 3;
                int liveSummaryIntervalSeconds = section.GetValue<int?>("LiveSummaryIntervalSeconds") ?? 5;

                return new TrafficCaptureService(flowIdleTimeoutSeconds, preFilterMinPackets, liveSummaryIntervalSeconds);
            });

            // 先清理遗留规则，再启动抓包
            // Clean up old rules before capture starts
            builder.Services.AddHostedService<FirewallRuleSweeper>();

            //add the registe background broadcast service
            builder.Services.AddHostedService<TrafficBroadcastService>();

            // Clears the live traffic window every 24 hours.
            builder.Services.AddHostedService<LiveTrafficWindowService>();

            builder.Host.UseWindowsService();

            //Tray icon only in desktop mode, not when running as a Windows service.
            if (!WindowsServiceHelpers.IsWindowsService())
            {
                builder.Services.AddHostedService<TrayIconService>();
            }

            builder.Services.AddDbContext<SentinelDbContext>(options =>
            options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

            builder.Services.AddDefaultIdentity<ApplicationUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = false;
                options.Password.RequiredLength = 6;
            })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<SentinelDbContext>();
            //   dotnet user-secrets set "AdminSeed:Password" "..." --project PolarisSentinel.Web
            // 初始管理员账号配置（密码来自 user-secrets / 环境变量，不硬编码）
            // Initial admin account configuration (password from user-secrets / env var)
            builder.Services.Configure<AdminSeedOptions>(
                builder.Configuration.GetSection(AdminSeedOptions.SectionName));

            builder.Services.AddScoped<SentinelDbInitializer>();

            //Configure Login path and Access Denied path for the application cookie
            builder.Services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = "/Account/Login";
                options.AccessDeniedPath = "/Account/AccessDenied";
            });


            builder.Services.AddSingleton<DetectionStateService>();


            builder.Services.AddSingleton<CaptureControlService>();

            // Labeled test rows for the Inference Results page (default CSV or uploaded).
            builder.Services.AddSingleton<TestDatasetService>();

            // RF + IF models, wrapped by the combination service that runs the five configurations.
            string modelPath = Path.GetFullPath(Path.Combine(
                builder.Environment.ContentRootPath,
                builder.Configuration["Inference:ModelPath"] ?? "../ml/artifacts/rf_model.onnx"));
            string? anomalyModelPath = builder.Configuration["Inference:AnomalyModelPath"] is { } configured
                ? Path.GetFullPath(Path.Combine(builder.Environment.ContentRootPath, configured))
                : null;

            builder.Services.AddSingleton<IRandomForestModel>(_ => new RandomForestModel(modelPath));
            builder.Services.AddSingleton<IIsolationForestModel?>(sp =>
            {
                if (anomalyModelPath == null)
                {
                    return null;
                }
                var rf = (RandomForestModel)sp.GetRequiredService<IRandomForestModel>();
                return new IsolationForestModel(anomalyModelPath, rf.FeatureNames);
            });
            builder.Services.AddSingleton<IModelCombinationService>(sp => new ModelCombinationService(
                sp.GetRequiredService<IRandomForestModel>(),
                sp.GetRequiredService<IIsolationForestModel?>()));

            builder.Services.AddSingleton<IInferenceEngine>(sp =>
                new OnnxInferenceEngine(sp.GetRequiredService<IModelCombinationService>()));

            builder.Services.AddSingleton<EvaluationService>(sp =>
                new EvaluationService(sp.GetRequiredService<IModelCombinationService>()));

            // Cooldown timing.
            builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);

            // Policy engine evaluates alerts against the supplied policies.
            builder.Services.AddSingleton<IPolicyEngine>(sp =>
                new PolicyEngine(sp.GetRequiredService<ILogger<PolicyEngine>>()));

            // Firewall enforcer stages rules; the pipeline commits them after the alert exists.
            builder.Services.AddScoped<IFirewallEnforcer>(sp =>
                new WindowsFirewallEnforcer(
                    sp.GetRequiredService<IUnitOfWork>().Rules,
                    sp.GetRequiredService<IOptions<FirewallOptions>>(),
                    sp.GetRequiredService<TimeProvider>(),
                    sp.GetRequiredService<ILogger<WindowsFirewallEnforcer>>()));

            // Detection pipeline (capture verdict -> inference -> policy -> enforcement).
            builder.Services.AddScoped<IDetectionPipeline>(sp =>
                new DetectionPipeline(
                    sp.GetRequiredService<IInferenceEngine>(),
                    sp.GetRequiredService<IPolicyEngine>(),
                    sp.GetRequiredService<IFirewallEnforcer>(),
                    sp.GetRequiredService<IUnitOfWork>(),
                    sp.GetRequiredService<ILogger<DetectionPipeline>>()));

            // Detection persistence (single transaction boundary over SentinelDbContext)
            builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();
            builder.Services.AddScoped<IAlertRepository>(sp => sp.GetRequiredService<IUnitOfWork>().Alerts);

            // Long-term traffic history (persisted per-day so charts survive a restart).
            builder.Services.AddScoped<ITrafficRecordRepository, TrafficRecordRepository>();
            builder.Services.AddSingleton<TrafficHistoryService>();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
                app.UseHttpsRedirection();
            }

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            // Force a password change before any other page is reachable.
            app.Use(async (context, next) =>
            {
                if (context.User.Identity?.IsAuthenticated == true)
                {
                    var path = context.Request.Path.Value ?? string.Empty;
                    bool allowed = path.StartsWith("/Account/ChangePassword", StringComparison.OrdinalIgnoreCase)
                        || path.StartsWith("/Account/Logout", StringComparison.OrdinalIgnoreCase)
                        || path.StartsWith("/lib", StringComparison.OrdinalIgnoreCase)
                        || path.StartsWith("/css", StringComparison.OrdinalIgnoreCase)
                        || path.StartsWith("/js", StringComparison.OrdinalIgnoreCase);

                    if (!allowed)
                    {
                        var userManager = context.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
                        var user = await userManager.GetUserAsync(context.User);
                        if (user is { MustChangePassword: true })
                        {
                            context.Response.Redirect("/Account/ChangePassword");
                            return;
                        }
                    }
                }

                await next();
            });

            app.MapStaticAssets();

            // Web API 控制器（含防火墙接口）
            // Web API controllers (includes firewall endpoints)
            app.MapControllers();
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Dashboard}/{action=Index}/{id?}")
                .WithStaticAssets();
            app.MapHub<TrafficHub>("/trafficHub");

            // Load the bundled test dataset so the Charts page has rows before any upload.
            var datasetService = app.Services.GetRequiredService<TestDatasetService>();
            string defaultDataset = Path.GetFullPath(Path.Combine(
                app.Environment.ContentRootPath,
                builder.Configuration["Evaluation:DefaultDatasetPath"] ?? "../ml/artifacts/test_dataset.csv"));
            if (File.Exists(defaultDataset))
            {
                try
                {
                    if (!datasetService.Load(Path.GetFileName(defaultDataset), File.ReadAllText(defaultDataset), out string? loadError))
                    {
                        app.Logger.LogWarning("Default test dataset rejected: {Error}", loadError);
                    }
                }
                catch (Exception ex)
                {
                    app.Logger.LogError(ex, "Failed to load the default test dataset");
                }
            }
            else
            {
                app.Logger.LogInformation("No default test dataset at {Path}", defaultDataset);
            }

            // 检测状态 API，页面加载时拉取
            // Detection state API for page load
            app.MapGet("/api/detections/state", (DetectionStateService state)=>Results.Json(state.GetSnapshot()))
                .RequireAuthorization();

            // Per-minute traffic series for the whole day, for the dashboard line chart.
            app.MapGet("/api/detections/traffic-series", (DetectionStateService state) => Results.Json(state.GetTrafficSeries()))
                .RequireAuthorization();

            // Dashboard card data: active rule count and the current AI model combination.
            app.MapGet("/api/dashboard/info", (IFirewallEnforcer firewall, IModelCombinationService combinations) =>
                Results.Json(new
                {
                    activeRules = firewall.GetAllRules().Count(r => r.Status == Core.Enums.RuleStatus.Active),
                    // The enum name is what the <select> option values use; the display name is for humans.
                    activeModel = combinations.ActiveCombination.ToString(),
                    activeModelDisplay = Core.Constants.ModelCombinations.DisplayName(combinations.ActiveCombination)
                }))
                .RequireAuthorization();

            // Change the live AI model combination from the dashboard.
            app.MapPost("/api/dashboard/model", (SetActiveModelRequest request, IModelCombinationService combinations) =>
            {
                if (!Enum.TryParse<Core.Enums.ModelCombination>(request.ModelCombination, out var combination))
                {
                    return Results.BadRequest(new { error = "Unknown model combination." });
                }

                combinations.SetActiveCombination(combination);
                return Results.Json(new
                {
                    activeModel = combination.ToString(),
                    activeModelDisplay = Core.Constants.ModelCombinations.DisplayName(combination)
                });
            })
                .RequireAuthorization();

            //应用迁移并创建初始管理员（实现见SentinelDbInitializer）。
            //Apply migrations and provision admin (see SentinelDbInitializer).
            await using (var scope = app.Services.CreateAsyncScope())
            {
                try
                {
                    var initializer = scope.ServiceProvider.GetRequiredService<SentinelDbInitializer>();
                    await initializer.InitializeAsync();

                }
                catch (Exception ex)
                {
                    app.Logger.LogError(ex,
                        "Database initialisation failed; check the connection and migrations.");
                    //迁移或种子失败时中止启动，避免无库状态下跑抓包/检测。
                    //Abort startup on migration/seed failure so capture does not run without DB.
                    throw;
                }
            }

            //Run the application
            app.Run();
        }
    }

    // Request body for changing the live AI model combination.
    public class SetActiveModelRequest
    {
        public string? ModelCombination { get; set; }
    }
}

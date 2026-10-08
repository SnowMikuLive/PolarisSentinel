using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Services;
using PolarisSentinel.Inference;
using PolarisSentinel.TrafficCapture;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PolarisSentinel.DataAccess.Data;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PolarisSentinel.Web.Hubs;
using PolarisSentinel.Web.Middleware;
using PolarisSentinel.Web.Service;
using PolarisSentinel.FirewallEnforement;
using PolarisSentinel.Application;
using PolarisSentinel.Application.Evaluation;
using PolarisSentinel.PolicyDecision;
using Microsoft.Extensions.Hosting.WindowsServices;
using PolarisSentinel.DataAccess.Repository;
namespace PolarisSentinel
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddControllersWithViews();

            // camelCase JSON so frontend JS can read properties directly.
            builder.Services.AddSignalR()
                .AddJsonProtocol(options =>
                {
                    options.PayloadSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
                });

            // Firewall configuration (DryRun, sweep interval).
            builder.Services.Configure<FirewallOptions>(
                builder.Configuration.GetSection("Firewall"));

            // Persisted user choices (dry-run, model combination, capture device, heuristic
            // switch) live in the database (single row), so they follow the database instead
            // of the Windows account.
            builder.Services.AddSingleton<IUserSettingsStore, DbUserSettingsStore>();

            // Runtime-toggleable heuristic detection (dashboard switch), persisted like the
            // other user settings.
            builder.Services.AddSingleton(sp => new DetectionRuntimeState(
                heuristicEnabled: true,
                sp.GetRequiredService<IUserSettingsStore>()));

            // Runtime-toggleable enforcement state, seeded from configuration or the user's
            // saved choice. The dashboard can flip DryRun after startup; a singleton so every
            // enforcer sees the change.
            builder.Services.AddSingleton(sp => new FirewallRuntimeState(
                sp.GetRequiredService<IOptions<FirewallOptions>>().Value.DryRun,
                sp.GetRequiredService<IUserSettingsStore>()));

            // Traffic capture runs on machine-wide defaults; per-user tuning is applied by the pipeline.
            builder.Services.AddSingleton<ITrafficCaptureService>(sp =>
            {
                var config = sp.GetRequiredService<IConfiguration>();
                var section = config.GetSection("PolicySettings");

                int flowIdleTimeoutSeconds = (section.GetValue<int?>("FlowIdleTimeoutMilliseconds") ?? 120000) / 1000;
                int liveSummaryIntervalSeconds = section.GetValue<int?>("LiveSummaryIntervalSeconds") ?? 5;

                // Detection sensitivity preset (High/Balanced/Low). Individual thresholds
                // may still be overridden here; null keeps the preset value.
                var sensitivity = DetectionThresholds.ParseSensitivity(section.GetValue<string>("Sensitivity"));
                var thresholds = DetectionThresholds.Resolve(
                    sensitivity,
                    minPackets: section.GetValue<int?>("PreFilterMinPackets"),
                    portScanDistinctPorts: section.GetValue<int?>("PortScanDistinctPorts"),
                    portScanMaxPacketsPerPort: section.GetValue<int?>("PortScanMaxPacketsPerPort"),
                    globalFloodPackets: section.GetValue<int?>("GlobalFloodPackets"),
                    globalFloodDistinctSources: section.GetValue<int?>("GlobalFloodDistinctSources"));

                return new TrafficCaptureService(flowIdleTimeoutSeconds, thresholds, liveSummaryIntervalSeconds,
                    sp.GetRequiredService<DetectionRuntimeState>());
            });

            // Clean up old rules before capture starts.
            builder.Services.AddHostedService<FirewallRuleSweeper>();

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

            // Initial admin account (password from user-secrets / env var).
            builder.Services.Configure<AdminSeedOptions>(
                builder.Configuration.GetSection(AdminSeedOptions.SectionName));

            builder.Services.AddScoped<SentinelDbInitializer>();

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
                sp.GetRequiredService<IIsolationForestModel?>(),
                ModelCombination.RandomForestOnly,
                sp.GetRequiredService<IUserSettingsStore>()));

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
                    sp.GetRequiredService<FirewallRuntimeState>(),
                    sp.GetRequiredService<TimeProvider>(),
                    sp.GetRequiredService<ILogger<WindowsFirewallEnforcer>>()));

            // Detection pipeline (capture verdict -> inference -> policy -> enforcement).
            builder.Services.AddScoped<IDetectionPipeline>(sp =>
                new DetectionPipeline(
                    sp.GetRequiredService<IInferenceEngine>(),
                    sp.GetRequiredService<IPolicyEngine>(),
                    sp.GetRequiredService<IFirewallEnforcer>(),
                    sp.GetRequiredService<IUnitOfWork>(),
                    sp.GetRequiredService<ILogger<DetectionPipeline>>(),
                    sp.GetRequiredService<DetectionRuntimeState>()));

            // Application use case: process one completed flow against the enabled policies.
            builder.Services.AddScoped<FlowProcessingService>();

            // Application use case: manual firewall-rule management.
            builder.Services.AddScoped<RuleManagementService>();

            // Application use case: policy validation and id assignment.
            builder.Services.AddScoped<PolicyManagementService>();

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
                app.UseExceptionHandler("/error");
                app.UseHsts();
                app.UseHttpsRedirection();
            }

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            // Force a password change before any other page is reachable.
            app.UseMiddleware<MustChangePasswordMiddleware>();

            app.MapStaticAssets();

            // Web API controllers (includes firewall endpoints).
            app.MapControllers();
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Dashboard}/{action=Index}/{id?}")
                .WithStaticAssets();
            app.MapHub<TrafficHub>("/trafficHub");

            // Target of UseExceptionHandler in Production (no HomeController in this app).
            app.MapGet("/error", () => Results.Problem(statusCode: StatusCodes.Status500InternalServerError));

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

            // Apply migrations and provision admin (see SentinelDbInitializer).
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
                    // Abort startup on migration/seed failure so capture does not run without a DB.
                    throw;
                }
            }

            //Run the application
            app.Run();
        }
    }
}

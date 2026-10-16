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

            // Accept the antiforgery request token from the "RequestVerificationToken" header as
            // well as a form field. HeaderName defaults to null (form fields only), which makes
            // JavaScript AJAX POSTs to MVC actions marked [ValidateAntiForgeryToken] fail with an
            // empty 400 response because a JSON request body carries no form field for the token.
            builder.Services.AddAntiforgery(options => options.HeaderName = "RequestVerificationToken");

            builder.Services.AddSignalR()
                .AddJsonProtocol(options =>
                {
                    options.PayloadSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
                });

            builder.Services.Configure<FirewallOptions>(
                builder.Configuration.GetSection("Firewall"));

            builder.Services.AddSingleton<IUserSettingsStore, DbUserSettingsStore>();

            builder.Services.AddSingleton(sp => new DetectionRuntimeState(
                heuristicEnabled: true,
                sp.GetRequiredService<IUserSettingsStore>()));

            builder.Services.AddSingleton<BlockedTrafficState>();

            builder.Services.AddSingleton(sp => new FirewallRuntimeState(
                sp.GetRequiredService<IOptions<FirewallOptions>>().Value.DryRun,
                sp.GetRequiredService<IUserSettingsStore>()));

            builder.Services.AddSingleton<ITrafficCaptureService>(sp =>
            {
                var config = sp.GetRequiredService<IConfiguration>();
                var section = config.GetSection("PolicySettings");

                int flowIdleTimeoutSeconds = (section.GetValue<int?>("FlowIdleTimeoutMilliseconds") ?? 120000) / 1000;
                int liveSummaryIntervalSeconds = section.GetValue<int?>("LiveSummaryIntervalSeconds") ?? 5;

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

            builder.Services.AddHostedService<FirewallRuleSweeper>();

            builder.Services.AddHostedService<TrafficBroadcastService>();

            builder.Services.AddHostedService<LiveTrafficWindowService>();

            builder.Host.UseWindowsService();

            if (!WindowsServiceHelpers.IsWindowsService())
            {
                builder.Services.AddHostedService<TrayIconService>();
            }

            builder.Services.AddDbContext<SentinelDbContext>(options =>
            options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

            builder.Services.AddDefaultIdentity<ApplicationUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = false;
                options.Password.RequiredLength = 8;
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;

                // Lock the account after repeated failed sign-ins instead of allowing
                // unlimited password guessing.
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
            })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<SentinelDbContext>();

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

            builder.Services.AddSingleton<TestDatasetService>();

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

            builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);

            builder.Services.AddSingleton<IPolicyEngine>(sp =>
                new PolicyEngine(sp.GetRequiredService<ILogger<PolicyEngine>>()));

            builder.Services.AddSingleton<IFirewallGateway>(sp =>
                new WindowsFirewallGateway(
                    sp.GetRequiredService<FirewallRuntimeState>(),
                    sp.GetRequiredService<ILogger<WindowsFirewallGateway>>()));

            builder.Services.AddScoped<IFirewallEnforcer>(sp =>
                new WindowsFirewallEnforcer(
                    sp.GetRequiredService<IUnitOfWork>().Rules,
                    sp.GetRequiredService<IFirewallGateway>(),
                    sp.GetRequiredService<FirewallRuntimeState>(),
                    sp.GetRequiredService<TimeProvider>(),
                    sp.GetRequiredService<ILogger<WindowsFirewallEnforcer>>()));

            builder.Services.AddScoped<IDetectionPipeline>(sp =>
                new DetectionPipeline(
                    sp.GetRequiredService<IInferenceEngine>(),
                    sp.GetRequiredService<IPolicyEngine>(),
                    sp.GetRequiredService<IFirewallEnforcer>(),
                    sp.GetRequiredService<IUnitOfWork>(),
                    sp.GetRequiredService<ILogger<DetectionPipeline>>(),
                    sp.GetRequiredService<DetectionRuntimeState>(),
                    sp.GetRequiredService<BlockedTrafficState>()));

            builder.Services.AddScoped<FlowProcessingService>();

            builder.Services.AddScoped<RuleManagementService>();

            builder.Services.AddScoped<PolicyManagementService>();

            builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();
            builder.Services.AddScoped<IAlertRepository>(sp => sp.GetRequiredService<IUnitOfWork>().Alerts);

            builder.Services.AddScoped<ITrafficRecordRepository, TrafficRecordRepository>();
            builder.Services.AddSingleton<TrafficHistoryService>();

            var app = builder.Build();

            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/error");
                app.UseHsts();
                app.UseHttpsRedirection();
            }

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseMiddleware<MustChangePasswordMiddleware>();

            app.MapStaticAssets();

            app.MapControllers();
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Dashboard}/{action=Index}/{id?}")
                .WithStaticAssets();
            // The dashboard feed carries the full flow 5-tuple, the attack type and the
            // firewall action, so it must never be readable without a signed-in session.
            app.MapHub<TrafficHub>("/trafficHub").RequireAuthorization();

            app.MapGet("/error", () => Results.Problem(statusCode: StatusCodes.Status500InternalServerError));

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
                    throw;
                }
            }

            app.Run();
        }
    }
}

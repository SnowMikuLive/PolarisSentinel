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
using PolarisSentinel.Web.Logging;
using PolarisSentinel.Web.Startup;
using PolarisSentinel.Web.Controllers;
namespace PolarisSentinel
{
    public class Program
    {
        private Program()
        {
        }

        private static string? ResolveContentRoot()
        {
            string baseDirectory = AppContext.BaseDirectory;
            bool isDeployedLayout =
                File.Exists(Path.Combine(baseDirectory, "appsettings.json")) &&
                Directory.Exists(Path.Combine(baseDirectory, "wwwroot"));
            return isDeployedLayout ? baseDirectory : null;
        }
        private static void WriteStartupLog(string message)
        {
            if (StartupSupport.HasConsole)
            {
                Console.Error.WriteLine(message);
            }
        }

        public static async Task Main(string[] args)
        {
            StartupSupport.TryAttachToParentConsole();
            StartupSupport.CanShowDialog = OperatingSystem.IsWindows()
                && !WindowsServiceHelpers.IsWindowsService()
                && Environment.UserInteractive
                && !StartupSupport.HasConsole;

            AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            {
                string report = (e.ExceptionObject as Exception)?.ToString() ?? "Unknown failure.";

                if (StartupSupport.HasConsole)
                {
                    Console.Error.WriteLine(report);
                }

                StartupSupport.ShowError("Polaris Sentinel - fatal error", report);
            };

            // The builder is created before the prerequisite check so the check can follow the
            // configured connection string: a deployment pointed at a full SQL Server instance
            // does not need LocalDB to be installed.
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                Args = args,
                ContentRootPath = ResolveContentRoot(),
            });

            // The effective database target: the configured value, or the detected local SQL Server
            // instance when the configuration asks for LocalDB and LocalDB is not installed.
            string configuredConnection = builder.Configuration.GetConnectionString("DefaultConnection") ?? string.Empty;
            string connectionString = SqlTargetResolver.Resolve(configuredConnection);

            if (args.Any(a => string.Equals(a, "--check-prerequisites", StringComparison.OrdinalIgnoreCase)))
            {
                var report = PrerequisiteCheck.FindMissing(builder.Environment.ContentRootPath, connectionString,
                    builder.Configuration["Inference:ModelPath"]);

                Console.Error.WriteLine(report.Count == 0
                    ? "All prerequisites were detected."
                    : PrerequisiteCheck.Describe(report));

                Environment.ExitCode = report.Count == 0 ? 0 : 2;
                return;
            }

            // A machine that has never run this application usually has no local database at all.
            // Offer to download and install SQL Server LocalDB instead of failing with a
            // "missing prerequisite" dialog that the user cannot act on.
            if (!PrerequisiteCheck.IsSkipped(args)
                && PrerequisiteCheck.RequiresLocalDb(connectionString)
                && !PrerequisiteCheck.IsLocalDbInstalled()
                && LocalDbInstaller.IsEnabled(args))
            {
                bool consented = LocalDbInstaller.IsUnattended(args)
                    || (StartupSupport.CanShowDialog
                        && StartupSupport.AskToContinue("Polaris Sentinel", LocalDbInstaller.Explain()));

                if (consented && await LocalDbInstaller.InstallAsync(WriteStartupLog))
                {
                    connectionString = SqlTargetResolver.Resolve(configuredConnection);

                    StartupSupport.ShowInfo(
                        "Polaris Sentinel",
                        "SQL Server LocalDB is installed. The database is created automatically on first start.");
                }
            }

            if (!PrerequisiteCheck.IsSkipped(args))
            {
                var missing = PrerequisiteCheck.FindMissing(builder.Environment.ContentRootPath, connectionString,
                    builder.Configuration["Inference:ModelPath"]);

                if (missing.Count > 0)
                {
                    string report = PrerequisiteCheck.Describe(missing);

                    if (StartupSupport.HasConsole)
                    {
                        await Console.Error.WriteLineAsync(report);
                    }

                    StartupSupport.ShowError("Polaris Sentinel - missing prerequisite", report);
                    Environment.ExitCode = 2;
                    return;
                }

                if (!StartupSupport.IsAdministrator())
                {
                    string warning =
                        "Polaris Sentinel is not running with administrator rights." + Environment.NewLine +
                        Environment.NewLine +
                        "Packet capture and Windows Firewall rules both need elevation, so this session will " +
                        "record dry-run decisions only and cannot block anything." + Environment.NewLine +
                        Environment.NewLine +
                        "Right-click the application and choose \"Run as administrator\" for full functionality.";

                    if (StartupSupport.HasConsole)
                    {
                        await Console.Error.WriteLineAsync("WARNING: " + warning);
                    }
                    else if (!StartupSupport.AskToContinue(
                        "Polaris Sentinel",
                        warning + Environment.NewLine + Environment.NewLine + "Continue anyway?"))
                    {
                        Environment.ExitCode = 3;
                        return;
                    }
                }
            }

            builder.Logging.ClearProviders();

            builder.Logging.AddSimpleConsole(options => options.SingleLine = true);

            string logDirectory = builder.Configuration["Logging:File:Directory"] is { Length: > 0 } configuredLogs
                ? Path.GetFullPath(Path.Combine(builder.Environment.ContentRootPath, configuredLogs))
                : Path.Combine(builder.Environment.ContentRootPath, "logs");

            builder.Logging.AddProvider(new FileLoggerProvider(
                logDirectory,
                builder.Configuration.GetValue<int?>("Logging:File:RetainedFileCount") ?? 7));

            builder.Services.AddControllersWithViews();

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
                    sp.GetRequiredService<DetectionRuntimeState>(),
                    sp.GetRequiredService<ILogger<TrafficCaptureService>>());
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
            options.UseSqlServer(connectionString));

            builder.Services.AddDefaultIdentity<ApplicationUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = false;
                options.Password.RequiredLength = 8;
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;

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

            string modelPath = PrerequisiteCheck.ResolveArtifactPath(
                builder.Environment.ContentRootPath,
                builder.Configuration["Inference:ModelPath"],
                "rf_model.onnx");
            string? anomalyModelPath = PrerequisiteCheck.ResolveArtifactPath(
                builder.Environment.ContentRootPath,
                builder.Configuration["Inference:AnomalyModelPath"],
                "if_model.onnx");

            builder.Services.AddSingleton<IRandomForestModel>(_ => new RandomForestModel(modelPath));
            if (!File.Exists(anomalyModelPath)) anomalyModelPath = null;
            if (anomalyModelPath is not null)
            {
                string resolvedAnomalyModelPath = anomalyModelPath;
                builder.Services.AddSingleton<IIsolationForestModel>(sp =>
                {
                    var rf = (RandomForestModel)sp.GetRequiredService<IRandomForestModel>();
                    return new IsolationForestModel(resolvedAnomalyModelPath, rf.FeatureNames);
                });
            }
            builder.Services.AddSingleton<IModelCombinationService>(sp => new ModelCombinationService(
                sp.GetRequiredService<IRandomForestModel>(),
                sp.GetService<IIsolationForestModel>(),
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
                    sp.GetRequiredService<ILogger<WindowsFirewallEnforcer>>(),
                    sp.GetRequiredService<BlockedTrafficState>()));

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

            app.Use(async (context, next) =>
            {
                context.Response.OnStarting(() =>
                {
                    context.Response.Headers["X-Frame-Options"] = "DENY";
                    context.Response.Headers["Content-Security-Policy"] =
                        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
                        "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' ws: wss:; " +
                        "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
                    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
                    context.Response.Headers["Referrer-Policy"] = "no-referrer";

                    if (context.Request.IsHttps)
                    {
                        context.Response.Headers["Strict-Transport-Security"] =
                            "max-age=31536000; includeSubDomains";
                    }

                    return Task.CompletedTask;
                });

                await next();
            });

            if (!string.Equals(connectionString, configuredConnection, StringComparison.Ordinal))
            {
                app.Logger.LogWarning(
                    "ConnectionStrings:DefaultConnection ({Configured}) cannot be used on this machine; " +
                    "falling back to the detected local SQL Server instance: {Target}",
                    SqlTargetResolver.Describe(configuredConnection),
                    SqlTargetResolver.Describe(connectionString));
            }
            else if (app.Logger.IsEnabled(LogLevel.Information))
            {
                app.Logger.LogInformation("Database target: {Target}", SqlTargetResolver.Describe(connectionString));
            }

            if (app.Logger.IsEnabled(LogLevel.Information))
            {
                app.Logger.LogInformation("Random Forest model: {Path}", modelPath);
            }

            if (anomalyModelPath is not null && app.Logger.IsEnabled(LogLevel.Information))
            {
                app.Logger.LogInformation("Isolation Forest model: {Path}", anomalyModelPath);
            }

            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/error");
                app.UseHttpsRedirection();
            }

            // An upload that exceeds the request size limit is refused by the host before the action
            // runs, so the form's own message never gets a chance to render. Answer with the same
            // explanation instead of a bare 400/413.
            app.UseStatusCodePages(async context =>
            {
                var response = context.HttpContext.Response;
                var request = context.HttpContext.Request;

                if (response.StatusCode is not (StatusCodes.Status400BadRequest or StatusCodes.Status413RequestEntityTooLarge) ||
                    !HttpMethods.IsPost(request.Method) ||
                    request.ContentType?.StartsWith("multipart/form-data", StringComparison.OrdinalIgnoreCase) != true)
                {
                    return;
                }

                response.ContentType = "text/html; charset=utf-8";
                await response.WriteAsync(
                    "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\" /><title>Upload rejected</title></head>"
                    + "<body style=\"font-family:system-ui,'Segoe UI',sans-serif;margin:3rem;color:#212529\">"
                    + "<h2 style=\"color:#B02A37\">The uploaded file is too large</h2>"
                    + $"<p>The Charts page accepts CSV files up to {ChartsController.MaxUploadBytes / 1048576} MB, "
                    + "and this request was refused before the file could be read.</p>"
                    + "<p>Split the dataset into smaller files, or load a representative sample.</p>"
                    + "<p><a href=\"/Charts\">Back to Charts</a></p></body></html>");
            });

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

            app.MapHub<TrafficHub>("/trafficHub").RequireAuthorization();

            app.MapGet("/error", () => Results.Problem(statusCode: StatusCodes.Status500InternalServerError));

            var datasetService = app.Services.GetRequiredService<TestDatasetService>();
            string defaultDataset = PrerequisiteCheck.ResolveArtifactPath(
                app.Environment.ContentRootPath,
                builder.Configuration["Evaluation:DefaultDatasetPath"],
                "test_dataset.csv");
            if (File.Exists(defaultDataset))
            {
                try
                {
                    string datasetContent = await File.ReadAllTextAsync(defaultDataset);
                    if (!datasetService.Load(Path.GetFileName(defaultDataset), datasetContent, out string? loadError, out int skippedRows))
                    {
                        app.Logger.LogWarning("Default test dataset rejected: {Error}", loadError);
                    }
                    else if (skippedRows > 0)
                    {
                        app.Logger.LogWarning("Default test dataset: skipped {Skipped} row(s) with invalid values", skippedRows);
                    }
                }
                catch (Exception ex)
                {
                    app.Logger.LogError(ex, "Failed to load the default test dataset");
                }
            }
            else if (app.Logger.IsEnabled(LogLevel.Information))
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

                    StartupSupport.ShowError(
                        "Polaris Sentinel - database error",
                        "The database could not be initialised." + Environment.NewLine + Environment.NewLine +
                        ex.Message + Environment.NewLine + Environment.NewLine +
                        "Check that the SQL Server instance named in ConnectionStrings:DefaultConnection " +
                        "is running and reachable, then see the log file next to the executable.");

                    throw new InvalidOperationException("Database initialisation failed.", ex);
                }
            }

            await app.RunAsync();
        }
    }
}

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

namespace PolarisSentinel
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            //builder.Service
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddControllersWithViews();

            //Add SignalR
            builder.Services.AddSignalR();

            // 策略配置热重载
            // Policy settings hot-reload
            builder.Services.Configure<PolicySettings>(
                builder.Configuration.GetSection("PolicySettings"));

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

            //add the registe background broadcast service
            builder.Services.AddHostedService<TrafficBroadcastService>();

            builder.Host.UseWindowsService();

            builder.Services.AddDbContext<ApplicationDbContext>(options =>
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

            //Register global detection state service as singleton
            builder.Services.AddSingleton<DetectionStateService>(); 





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
            builder.Services.AddSingleton<IPolicyEngine, PolicyEngine>();

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
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}")
                .WithStaticAssets();
            app.MapHub<TrafficHub>("/trafficHub");

            //Expose detection state API, fetched by fronted on page Load
            app.MapGet("/api/detections/state", (DetectionStateService state)=>Results.Json(state.GetSnapshot()));

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
                        "Identity database initialisation failed; login is unavailable until the database is reachable.");
                }
            }

            //Run the application
            app.Run();
        }
    }
}

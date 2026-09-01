using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Hubs;
using PolarisSentinel.Inference;
using PolarisSentinel.Services;
using PolarisSentinel.TrafficCapture;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Web.Data;
using Microsoft.Extensions.DependencyInjection;

namespace PolarisSentinel
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddControllersWithViews();
            builder.Host.UseWindowsService();
            builder.Services.AddSignalR();

            builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

            //Add DbContext service
            builder.Services.AddDefaultIdentity<IdentityUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = false;
                options.Password.RequiredLength = 6;
            })
                .AddEntityFrameworkStores<ApplicationDbContext>();

            // Program.cs

            string modelPath = Path.GetFullPath(Path.Combine(
                builder.Environment.ContentRootPath,
                builder.Configuration["Inference:ModelPath"] ?? "../ml/artifacts/rf_model.onnx"));
            builder.Services.AddSingleton(_ => new OnnxInferenceEngine(modelPath));
            builder.Services.AddSingleton<IInferenceEngine>(
                sp => sp.GetRequiredService<OnnxInferenceEngine>());

            if (builder.Configuration.GetValue("Demo:Enabled", false))
            {
                builder.Services.AddHostedService<DemoReplayService>();
            }

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
            app.MapHub<DetectionHub>("/hubs/detections");

            app.MapGet("/api/demo/info", (OnnxInferenceEngine engine) => Results.Json(new
            {
                classes = engine.ClassNames,
                featureCount = engine.FeatureNames.Count,
                rfThreshold = engine.RfConfidenceThreshold,
                blockThreshold = engine.AutoBlockConfidenceThreshold,
            }));

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
            app.Run();
        }
    }
}

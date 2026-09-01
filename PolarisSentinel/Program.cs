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
        public static async Task Main(string[] args)//use await which can wait for database completing. To run the application asynchronously
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
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
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

            //Default Admin User Create
            using (var scope = app.Services.CreateScope())
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
                var admin = await userManager.FindByNameAsync("admin");

                //Start to create the default admin user if it does not exist. 
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
                            Console.WriteLine($"Failed to create admin user: {error.Description}");
                        }
                    }
                }
            }
            app.Run();
        }
    }
}

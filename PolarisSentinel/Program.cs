using PolarisSentinel.TrafficCapture;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Web.Data;
using Microsoft.Extensions.DependencyInjection; 
using PolarisSentinel.Web.Hubs;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Web.Service;

namespace PolarisSentinel
{
    public class Program
    {
        public static async Task Main(string[] args)//use await which can wait for database completing. To run the application asynchronously
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddControllersWithViews();

            //Add SignalR
            builder.Services.AddSignalR();


            //Register the ITrafficCaptureService as a singleton service
            //sp is the service provider that allows you to resolve other services from the DI container. In this case, we are resolving IConfiguration to read the configuration values for the TrafficCaptureService.
            builder.Services.AddSingleton<ITrafficCaptureService>(sp =>
            {

                var config=sp.GetRequiredService<IConfiguration>();
                var section= config.GetSection("PolicySettings");
                int flowIdleTimeoutSeconds = section.GetValue<int>("FlowIdleTimeoutSeconds");
                int preFilterMinPackets = section.GetValue<int>("PreFilterMinPackets");

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

            //map the SignalR hub endpoint
            app.MapHub<TrafficHub>("/trafficHub");

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

            //Run the application
            app.Run();
        }
    }
}

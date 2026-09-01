using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Hubs;
using PolarisSentinel.Inference;
using PolarisSentinel.Services;

namespace PolarisSentinel
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddControllersWithViews();
            builder.Host.UseWindowsService();
            builder.Services.AddSignalR();

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

            app.Run();
        }
    }
}

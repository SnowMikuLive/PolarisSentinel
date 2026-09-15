using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace PolarisSentinel.Web.Service;

// Shows a tray icon that opens the web dashboard. Only runs when the app is
// started as a desktop app, not as a Windows service (no UI in session 0).
public class TrayIconService : IHostedService, IDisposable
{
    private readonly IConfiguration _config;
    private readonly ILogger<TrayIconService> _logger;
    private NotifyIcon? _icon;

    public TrayIconService(IConfiguration config, ILogger<TrayIconService> logger)
    {
        _config = config;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            _icon = new NotifyIcon
            {
                Text = "Polaris Sentinel",
                Icon = SystemIcons.Shield,
                Visible = true
            };

            var menu = new ContextMenuStrip();
            menu.Items.Add("Open Dashboard", null, (_, _) => OpenDashboard());
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Exit", null, (_, _) => Exit());

            _icon.ContextMenuStrip = menu;
            _icon.DoubleClick += (_, _) => OpenDashboard();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Tray icon unavailable");
        }

        return Task.CompletedTask;
    }

    private void OpenDashboard()
    {
        var url = _config["Dashboard:Url"] ?? "http://localhost:5000";
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }

    private void Exit()
    {
        _icon?.Dispose();
        Environment.Exit(0);
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _icon?.Dispose();
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _icon?.Dispose();
    }
}

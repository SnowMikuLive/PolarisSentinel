using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Hosting;

namespace PolarisSentinel.Web.Service;

public sealed class TrayIconService : IHostedService, IDisposable
{
    private readonly IConfiguration _config;
    private readonly IServer _server;
    private readonly ILogger<TrayIconService> _logger;
    private readonly IHostApplicationLifetime _lifetime;
    private System.Windows.Forms.ApplicationContext? _context;
    private NotifyIcon? _icon;
    private DateTime _lastOpenAt = DateTime.MinValue;

    public TrayIconService(
        IConfiguration config,
        IServer server,
        ILogger<TrayIconService> logger,
        IHostApplicationLifetime lifetime)
    {
        _config = config;
        _server = server;
        _logger = logger;
        _lifetime = lifetime;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        var thread = new Thread(RunMessageLoop)
        {
            IsBackground = true,
            Name = "TrayIcon"
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        return Task.CompletedTask;
    }

    private void RunMessageLoop()
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
            _icon.MouseClick += (_, e) =>
            {
                if (e.Button == MouseButtons.Left)
                {
                    OpenDashboard();
                }
            };

            string dashboardUrl = ResolveDashboardUrl();
            if (_logger.IsEnabled(LogLevel.Information))
            {
                _logger.LogInformation("Polaris Sentinel is running. Dashboard: {Url}", dashboardUrl);
            }

            _icon.ShowBalloonTip(
                15000,
                "Polaris Sentinel",
                "Running in the background." + Environment.NewLine + "Open the dashboard: " + dashboardUrl,
                ToolTipIcon.Info);

            _context = new System.Windows.Forms.ApplicationContext();
            System.Windows.Forms.Application.Run(_context);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Tray icon unavailable");
        }
    }

    private void OpenDashboard()
    {
        if (DateTime.UtcNow - _lastOpenAt < TimeSpan.FromSeconds(2))
        {
            return;
        }

        _lastOpenAt = DateTime.UtcNow;

        var url = ResolveDashboardUrl();
        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation("Opening dashboard at {Url}", url);
        }
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to open dashboard at {Url}", url);
        }
    }

    private string ResolveDashboardUrl()
    {
        var configured = _config["Dashboard:Url"];
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }

        var address = _server.Features.Get<IServerAddressesFeature>()?.Addresses.FirstOrDefault();
        return address ?? "http://localhost:5180";
    }

    private void Exit()
    {
        _icon?.Dispose();
        _context?.ExitThread();
        _logger.LogInformation("Exit requested from the tray icon; stopping the host gracefully");
        _lifetime.StopApplication();
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _icon?.Dispose();
        _context?.ExitThread();
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _icon?.Dispose();
        GC.SuppressFinalize(this);
    }
}

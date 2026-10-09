using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace PolarisSentinel.Web.Service;

// Shows a tray icon that opens the web dashboard. Only runs when the app is
// started as a desktop app, not as a Windows service (no UI in session 0).
//
// NotifyIcon needs a WinForms message loop to receive mouse events. ASP.NET Core
// has no such loop, so we run one on a dedicated STA thread.
public class TrayIconService : IHostedService, IDisposable
{
    private readonly IConfiguration _config;
    private readonly IServer _server;
    private readonly ILogger<TrayIconService> _logger;
    private Thread? _uiThread;
    private System.Windows.Forms.ApplicationContext? _context;
    private NotifyIcon? _icon;

    public TrayIconService(IConfiguration config, IServer server, ILogger<TrayIconService> logger)
    {
        _config = config;
        _server = server;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _uiThread = new Thread(RunMessageLoop)
        {
            IsBackground = true,
            Name = "TrayIcon"
        };
        _uiThread.SetApartmentState(ApartmentState.STA);
        _uiThread.Start();

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
        var url = ResolveDashboardUrl();
        _logger.LogInformation("Opening dashboard at {Url}", url);
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
        Environment.Exit(0);
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
    }
}

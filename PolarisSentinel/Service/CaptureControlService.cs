using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Service;

// Holds the current capture device and lets the UI switch it at runtime.
public class CaptureControlService
{
    private readonly ITrafficCaptureService _capture;
    private readonly ILogger<CaptureControlService> _logger;
    private readonly object _lock = new();
    private string? _currentDevice;

    public CaptureControlService(ITrafficCaptureService capture, ILogger<CaptureControlService> logger)
    {
        _capture = capture;
        _logger = logger;
    }

    public string? CurrentDevice => _currentDevice;

    // Auto-select: prefer Wi-Fi, then Ethernet, then the first device.
    public void AutoStart()
    {
        var devices = _capture.GetAvailableDevices().ToList();
        var selected = devices.FirstOrDefault(d =>
                d.DisplayName.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase)) ??
            devices.FirstOrDefault(d =>
                d.DisplayName.Contains("Ethernet", StringComparison.OrdinalIgnoreCase)) ??
            devices.FirstOrDefault();

        if (selected != null)
        {
            SwitchTo(selected.DeviceName);
        }
    }

    public IEnumerable<NetworkInterfaceInfo> GetDevices() => _capture.GetAvailableDevices();

    public bool SwitchTo(string deviceName)
    {
        lock (_lock)
        {
            try
            {
                _capture.Stop();
                _capture.Start(deviceName);
                _currentDevice = deviceName;
                _logger.LogInformation("Capture switched to {Device}", deviceName);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to switch capture to {Device}", deviceName);
                return false;
            }
        }
    }
}

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

    // Never let device enumeration throw: a failure here would return HTTP 500 from
    // /api/capture/devices and blank out the UI's network-interface selector.
    public IEnumerable<NetworkInterfaceInfo> GetDevices()
    {
        try
        {
            return _capture.GetAvailableDevices().ToList();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to enumerate capture devices");
            return Array.Empty<NetworkInterfaceInfo>();
        }
    }

    // Switches capture to the given device. Retries once, because a NIC that was
    // just hammered by a flood can briefly refuse to reopen; the retry re-resolves
    // the device from a freshly refreshed list.
    public bool SwitchTo(string deviceName)
    {
        lock (_lock)
        {
            if (string.Equals(_currentDevice, deviceName, StringComparison.Ordinal))
            {
                return true;
            }

            for (int attempt = 1; attempt <= 2; attempt++)
            {
                try
                {
                    _capture.Stop();
                    _capture.Start(deviceName);
                    _currentDevice = deviceName;
                    _logger.LogInformation("Capture switched to {Device} (attempt {Attempt})", deviceName, attempt);
                    return true;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to switch capture to {Device} (attempt {Attempt})", deviceName, attempt);
                }
            }

            return false;
        }
    }
}

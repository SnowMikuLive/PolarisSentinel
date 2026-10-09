using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Service;

// Holds the current capture device and lets the UI switch it at runtime.
public class CaptureControlService
{
    private readonly ITrafficCaptureService _capture;
    private readonly ILogger<CaptureControlService> _logger;
    private readonly IUserSettingsStore? _settings;
    private readonly object _lock = new();
    private string? _currentDevice;

    public CaptureControlService(ITrafficCaptureService capture, ILogger<CaptureControlService> logger, IUserSettingsStore? settings = null)
    {
        _capture = capture;
        _logger = logger;
        _settings = settings;
    }

    public string? CurrentDevice => _currentDevice;

    public void AutoStart()
    {
        var selected = GetDefaultDeviceName();
        if (selected != null)
        {
            SwitchTo(selected, persist: false);
        }
    }

    public string? GetDefaultDeviceName()
    {
        var devices = GetDevices().ToList();
        if (devices.Count == 0)
        {
            return null;
        }

        string? saved = _settings?.Read().CaptureDevice;
        if (!string.IsNullOrEmpty(saved) && devices.Any(d => d.DeviceName == saved))
        {
            return saved;
        }

        return devices[0].DeviceName;
    }

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

    public bool SwitchTo(string deviceName, bool persist = true)
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

                    if (persist)
                    {
                        _settings?.Update(s => s.CaptureDevice = deviceName);
                    }

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

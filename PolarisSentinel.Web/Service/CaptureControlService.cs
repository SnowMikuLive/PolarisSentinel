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

    // Auto-select: prefer the device the user last chose (it follows them across restarts),
    // then Wi-Fi, then Ethernet, then the first device.
    public void AutoStart()
    {
        var devices = _capture.GetAvailableDevices().ToList();
        string? saved = _settings?.Read().CaptureDevice;

        var selected =
            (!string.IsNullOrEmpty(saved) ? devices.FirstOrDefault(d => d.DeviceName == saved) : null) ??
            devices.FirstOrDefault(d =>
                d.DisplayName.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase)) ??
            devices.FirstOrDefault(d =>
                d.DisplayName.Contains("Ethernet", StringComparison.OrdinalIgnoreCase)) ??
            devices.FirstOrDefault();

        if (selected != null)
        {
            // Startup selection is not a user choice, so it is not persisted.
            SwitchTo(selected.DeviceName, persist: false);
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
    // the device from a freshly refreshed list. persist is true for an explicit user
    // choice, which is then saved and restored on the next start.
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

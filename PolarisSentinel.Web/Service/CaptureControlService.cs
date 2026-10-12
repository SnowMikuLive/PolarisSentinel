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
        if (selected is null)
        {
            _logger.LogWarning("No capture devices available; capture not started.");
            return;
        }

        var result = SwitchTo(selected, persist: false);
        if (!result.Success)
        {
            _logger.LogWarning("Auto-start on {Device} failed: {Error}", selected, result.Error);
        }
    }

    public string? GetDefaultDeviceName() => GetDefaultDeviceName(GetDevices().ToList());

    public string? GetDefaultDeviceName(IReadOnlyList<NetworkInterfaceInfo> devices)
    {
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

    public CaptureSwitchResult SwitchTo(string deviceName, bool persist = true)
    {
        if (string.IsNullOrWhiteSpace(deviceName))
        {
            return new CaptureSwitchResult(CaptureSwitchStatus.DeviceNotFound, null, "deviceName is required");
        }

        lock (_lock)
        {
            if (string.Equals(_currentDevice, deviceName, StringComparison.Ordinal))
            {
                return new CaptureSwitchResult(CaptureSwitchStatus.Success, deviceName, null);
            }

            // Reject an unknown device before tearing down a working capture. When enumeration
            // returned nothing we cannot pre-validate, so fall through and let Start report it.
            var devices = GetDevices().ToList();
            if (devices.Count > 0 && !devices.Any(d => d.DeviceName == deviceName))
            {
                return new CaptureSwitchResult(CaptureSwitchStatus.DeviceNotFound, null, $"No capture device named '{deviceName}'.");
            }

            string? previous = _currentDevice;
            CaptureSwitchStatus status = CaptureSwitchStatus.Failed;

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
                    return new CaptureSwitchResult(CaptureSwitchStatus.Success, deviceName, null);
                }
                catch (InvalidOperationException ex)
                {
                    status = CaptureSwitchStatus.DeviceNotFound;
                    _logger.LogWarning(ex, "Capture device {Device} not found (attempt {Attempt})", deviceName, attempt);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to switch capture to {Device} (attempt {Attempt})", deviceName, attempt);
                }
            }

            // The switch failed after Stop(), so capture is down. Report that honestly and
            // bring the previous device back if we can, so monitoring survives a bad selection.
            _currentDevice = null;
            if (!string.IsNullOrEmpty(previous) && !string.Equals(previous, deviceName, StringComparison.Ordinal))
            {
                try
                {
                    _capture.Start(previous);
                    _currentDevice = previous;
                    _logger.LogInformation("Restored capture on {Device} after a failed switch", previous);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to restore capture on {Device}", previous);
                }
            }

            string error = status == CaptureSwitchStatus.DeviceNotFound
                ? $"No capture device named '{deviceName}'."
                : $"Failed to start capture on '{deviceName}'.";

            return new CaptureSwitchResult(status, _currentDevice, error);
        }
    }
}

public enum CaptureSwitchStatus
{
    Success,
    DeviceNotFound,
    Failed
}

public readonly record struct CaptureSwitchResult(CaptureSwitchStatus Status, string? Device, string? Error)
{
    public bool Success => Status == CaptureSwitchStatus.Success;
}

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

        // A saved choice may be stored by device name or by friendly display name, so match
        // either. This keeps the operator's selection across libpcap device-name drift
        // (reboots, driver reinstalls, adapter re-enables).
        string? saved = _settings?.Read().CaptureDevice;
        var savedDevice = devices.FirstOrDefault(d => d.Matches(saved));
        if (savedDevice is not null)
        {
            return savedDevice.DeviceName;
        }

        // Otherwise choose a real, routable adapter instead of trusting enumeration order,
        // which can otherwise put loopback or a disconnected virtual NIC first.
        var fallback = devices.FirstOrDefault(d => !d.IsLoopback && !string.IsNullOrEmpty(d.IpAddress))
            ?? devices.FirstOrDefault(d => !d.IsLoopback)
            ?? devices[0];

        return fallback.DeviceName;
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
            // Fast path: re-selecting the active device is a no-op. This also avoids a
            // spurious "not found" when an adapter is still capturing but momentarily
            // missing from enumeration.
            if (string.Equals(_currentDevice, deviceName, StringComparison.OrdinalIgnoreCase))
            {
                return new CaptureSwitchResult(CaptureSwitchStatus.Success, _currentDevice, null);
            }

            // Resolve the requested name to the canonical device the capture layer knows, so
            // matching is consistent even when the caller passed the friendly display name or
            // a differently-cased value. When enumeration returned nothing we cannot
            // pre-validate, so fall through and let Start report the problem.
            var devices = GetDevices().ToList();
            if (devices.Count > 0)
            {
                var known = devices.FirstOrDefault(d => d.Matches(deviceName));
                if (known is null)
                {
                    return new CaptureSwitchResult(CaptureSwitchStatus.DeviceNotFound, null, $"No capture device named '{deviceName}'.");
                }

                deviceName = known.DeviceName;

                if (string.Equals(_currentDevice, deviceName, StringComparison.OrdinalIgnoreCase))
                {
                    return new CaptureSwitchResult(CaptureSwitchStatus.Success, deviceName, null);
                }
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
            if (!string.IsNullOrEmpty(previous) && !string.Equals(previous, deviceName, StringComparison.OrdinalIgnoreCase))
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

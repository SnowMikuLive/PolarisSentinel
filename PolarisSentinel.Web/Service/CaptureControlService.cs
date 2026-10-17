using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Service;

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
        var savedDevice = devices.FirstOrDefault(d => d.Matches(saved));
        if (savedDevice is not null)
        {
            return savedDevice.DeviceName;
        }

        var fallback = devices.FirstOrDefault(d => !d.IsLoopback && d.IsDefaultRoute)
            ?? devices.FirstOrDefault(d => !d.IsLoopback && !string.IsNullOrEmpty(d.IpAddress) && !LooksVirtual(d))
            ?? devices.FirstOrDefault(d => !d.IsLoopback && !string.IsNullOrEmpty(d.IpAddress))
            ?? devices.FirstOrDefault(d => !d.IsLoopback)
            ?? devices[0];

        return fallback.DeviceName;
    }

    private static bool LooksVirtual(NetworkInterfaceInfo device)
    {
        string[] markers =
        {
            "virtual", "vpn", "wi-fi direct", "loopback", "bluetooth", "hyper-v", "vmware", "tap-", "tunnel", "wan miniport", "pseudo"
        };

        return markers.Any(m => device.DisplayName.Contains(m, StringComparison.OrdinalIgnoreCase));
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

            if (string.Equals(_currentDevice, deviceName, StringComparison.OrdinalIgnoreCase))
            {
                return new CaptureSwitchResult(CaptureSwitchStatus.Success, _currentDevice, null);
            }

            var devices = ResolveRequestedDevice(deviceName);
            if (devices is null)
            {
                return new CaptureSwitchResult(CaptureSwitchStatus.DeviceNotFound, null, $"No capture device named '{deviceName}'.");
            }

            deviceName = devices;

            if (string.Equals(_currentDevice, deviceName, StringComparison.OrdinalIgnoreCase))
            {
                return new CaptureSwitchResult(CaptureSwitchStatus.Success, deviceName, null);
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

                    if (_logger.IsEnabled(LogLevel.Information))
                    {
                        _logger.LogInformation("Capture switched to {Device} (attempt {Attempt})", deviceName, attempt);
                    }
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

            _currentDevice = null;
            if (!string.IsNullOrEmpty(previous) && !string.Equals(previous, deviceName, StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    _capture.Start(previous);
                    _currentDevice = previous;
                    if (_logger.IsEnabled(LogLevel.Information))
                    {
                        _logger.LogInformation("Restored capture on {Device} after a failed switch", previous);
                    }
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

    private string? ResolveRequestedDevice(string deviceName)
    {
        var devices = GetDevices().ToList();
        if (devices.Count == 0)
        {
            return deviceName;
        }

        return devices.FirstOrDefault(d => d.Matches(deviceName))?.DeviceName;
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

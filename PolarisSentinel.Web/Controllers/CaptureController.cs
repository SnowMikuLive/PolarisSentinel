using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Web.Service;

namespace PolarisSentinel.Web.Controllers
{
    // API for listing and switching capture devices.
    [Authorize]
    [ApiController]
    [Route("api/capture")]
    public class CaptureController : ControllerBase
    {
        private readonly CaptureControlService _captureControl;

        public CaptureController(CaptureControlService captureControl)
        {
            _captureControl = captureControl;
        }

        [HttpGet("devices")]
        public IActionResult GetDevices()
        {
            var devices = _captureControl.GetDevices().ToList();
            var defaultDevice = _captureControl.GetDefaultDeviceName(devices);
            var current = _captureControl.CurrentDevice;

            var projection = devices
                .Select(d => new
                {
                    deviceName = d.DeviceName,
                    displayName = d.DisplayName,
                    ipAddress = d.IpAddress,
                    macAddress = d.MacAddress,
                    isLoopback = d.IsLoopback,
                    isCurrent = string.Equals(d.DeviceName, current, StringComparison.OrdinalIgnoreCase),
                    isDefault = string.Equals(d.DeviceName, defaultDevice, StringComparison.OrdinalIgnoreCase)
                })
                .ToList();

            return Ok(new { current, devices = projection });
        }

        [HttpPost("select")]
        public IActionResult Select([FromBody] SelectDeviceRequest request)
        {
            if (string.IsNullOrWhiteSpace(request?.DeviceName))
            {
                return BadRequest(new { error = "deviceName is required" });
            }

            var result = _captureControl.SwitchTo(request.DeviceName);

            return result.Status switch
            {
                CaptureSwitchStatus.Success => Ok(new { current = result.Device }),
                CaptureSwitchStatus.DeviceNotFound => NotFound(new { error = result.Error, current = result.Device }),
                _ => StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = result.Error, current = result.Device })
            };
        }
    }

    public class SelectDeviceRequest
    {
        public string? DeviceName { get; set; }
    }
}

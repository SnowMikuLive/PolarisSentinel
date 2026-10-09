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
            var defaultDevice = _captureControl.GetDefaultDeviceName();

            var devices = _captureControl.GetDevices()
                .Select(d => new
                {
                    deviceName = d.DeviceName,
                    displayName = d.DisplayName,
                    ipAddress = d.IpAddress,
                    isCurrent = d.DeviceName == _captureControl.CurrentDevice,
                    isDefault = d.DeviceName == defaultDevice
                })
                .ToList();

            return Ok(new { current = _captureControl.CurrentDevice, devices });
        }

        [HttpPost("select")]
        public IActionResult Select([FromBody] SelectDeviceRequest request)
        {
            if (string.IsNullOrWhiteSpace(request?.DeviceName))
            {
                return BadRequest(new { error = "deviceName is required" });
            }

            var ok = _captureControl.SwitchTo(request.DeviceName);
            if (!ok)
            {
                return NotFound(new { error = "device not found or failed to start" });
            }

            return Ok(new { current = _captureControl.CurrentDevice });
        }
    }

    public class SelectDeviceRequest
    {
        public string? DeviceName { get; set; }
    }
}

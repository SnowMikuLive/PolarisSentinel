using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Web.Service;

namespace PolarisSentinel.Web.Controllers;

// Detection state API consumed by the dashboard on page load. Extracted from Program.cs
// so the composition root stays wiring-only.
[Authorize]
[ApiController]
[Route("api/detections")]
public class DetectionApiController : ControllerBase
{
    private readonly DetectionStateService _state;

    public DetectionApiController(DetectionStateService state)
    {
        _state = state;
    }

    [HttpGet("state")]
    public IActionResult State() => Ok(_state.GetSnapshot());

    [HttpGet("traffic-series")]
    public IActionResult TrafficSeries() => Ok(_state.GetTrafficSeries());
}

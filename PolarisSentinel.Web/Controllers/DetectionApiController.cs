using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Web.Service;

namespace PolarisSentinel.Web.Controllers;

[Authorize]
[ApiController]
[Route("api/detections")]
public class DetectionApiController : ControllerBase
{
    private readonly DetectionStateService _state;
    private readonly IFirewallEnforcer _firewall;

    public DetectionApiController(DetectionStateService state, IFirewallEnforcer firewall)
    {
        _state = state;
        _firewall = firewall;
    }

    [HttpGet("state")]
    public IActionResult State() => Ok(_state.GetSnapshot(
        _firewall.GetAllRules().Count(r => r.Status == RuleStatus.Active)));

    [HttpGet("traffic-series")]
    public IActionResult TrafficSeries() => Ok(_state.GetTrafficSeries());
}

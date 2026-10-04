using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;

namespace PolarisSentinel.Web.Controllers;

// Dashboard card data and the live AI model switch. Extracted from Program.cs so the
// composition root stays wiring-only.
[Authorize]
[ApiController]
[Route("api/dashboard")]
public class DashboardApiController : ControllerBase
{
    private readonly IFirewallEnforcer _firewall;
    private readonly IModelCombinationService _combinations;

    public DashboardApiController(IFirewallEnforcer firewall, IModelCombinationService combinations)
    {
        _firewall = firewall;
        _combinations = combinations;
    }

    // Active rule count and the current AI model combination.
    [HttpGet("info")]
    public IActionResult Info()
    {
        return Ok(new
        {
            activeRules = _firewall.GetAllRules().Count(r => r.Status == RuleStatus.Active),
            // The enum name is what the <select> option values use; the display name is for humans.
            activeModel = _combinations.ActiveCombination.ToString(),
            activeModelDisplay = ModelCombinations.DisplayName(_combinations.ActiveCombination),
            // Surface dry-run so the operator knows enforcement is not actually happening.
            dryRun = _firewall.IsDryRun,
            dryRunReason = _firewall.DryRunReason
        });
    }

    // Change the live AI model combination from the dashboard.
    [HttpPost("model")]
    public IActionResult SetModel([FromBody] SetActiveModelRequest request)
    {
        if (!Enum.TryParse<ModelCombination>(request.ModelCombination, out var combination))
        {
            return BadRequest(new { error = "Unknown model combination." });
        }

        _combinations.SetActiveCombination(combination);
        return Ok(new
        {
            activeModel = combination.ToString(),
            activeModelDisplay = ModelCombinations.DisplayName(combination)
        });
    }

    // Turn firewall dry-run on/off from the dashboard.
    [HttpPost("dryrun")]
    public IActionResult SetDryRun([FromBody] SetDryRunRequest request)
    {
        var (dryRun, reason) = _firewall.SetDryRun(request.DryRun);
        return Ok(new { dryRun, dryRunReason = reason });
    }
}

// Request body for toggling firewall dry-run.
public class SetDryRunRequest
{
    public bool DryRun { get; set; }
}

// Request body for changing the live AI model combination.
public class SetActiveModelRequest
{
    public string? ModelCombination { get; set; }
}

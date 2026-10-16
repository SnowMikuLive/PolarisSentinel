using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Services;

namespace PolarisSentinel.Web.Controllers;

// Dashboard card data and the live AI model switch. Extracted from Program.cs so the
// composition root stays wiring-only.
[Authorize]
[ApiController]
[ValidateAntiForgeryToken]
[Route("api/dashboard")]
public class DashboardApiController : ControllerBase
{
    private readonly IFirewallEnforcer _firewall;
    private readonly IModelCombinationService _combinations;
    private readonly DetectionRuntimeState _detection;

    public DashboardApiController(IFirewallEnforcer firewall, IModelCombinationService combinations, DetectionRuntimeState detection)
    {
        _firewall = firewall;
        _combinations = combinations;
        _detection = detection;
    }

    [HttpGet("info")]
    public IActionResult Info()
    {
        return Ok(new
        {
            activeRules = _firewall.GetAllRules().Count(r => r.Status == RuleStatus.Active),
            activeModel = _combinations.ActiveCombination.ToString(),
            activeModelDisplay = ModelCombinations.DisplayName(_combinations.ActiveCombination),
            dryRun = _firewall.IsDryRun,
            dryRunReason = _firewall.DryRunReason,
            heuristicEnabled = _detection.HeuristicEnabled
        });
    }

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

    [HttpPost("dryrun")]
    public IActionResult SetDryRun([FromBody] SetDryRunRequest request)
    {
        var (dryRun, reason) = _firewall.SetDryRun(request.DryRun);
        return Ok(new { dryRun, dryRunReason = reason });
    }

    [HttpPost("heuristic")]
    public IActionResult SetHeuristic([FromBody] SetHeuristicRequest request)
    {
        return Ok(new { heuristicEnabled = _detection.SetHeuristicEnabled(request.HeuristicEnabled) });
    }
}

public class SetHeuristicRequest
{
    public bool HeuristicEnabled { get; set; }
}

public class SetDryRunRequest
{
    public bool DryRun { get; set; }
}

public class SetActiveModelRequest
{
    public string? ModelCombination { get; set; }
}

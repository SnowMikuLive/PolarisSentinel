using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Controllers
{
    //Rules API controller, used by AJAX only
    [Authorize]
    [ApiController]
    [Route("api/rules")]
    public class RulesApiController : Controller
    {

        //uow:Unit of Work. Used for unified management of database operations
        private readonly IUnitOfWork _uow;
        public RulesApiController(IUnitOfWork uow)
        {
            _uow = uow;
        }
        // Get /api/rules
        [HttpGet]
        public async Task<IActionResult> GetAll(CancellationToken cancellationToken)
        {
            //Retrieve this rule from the database
            var rules = await _uow.Rules.GetAllAsync(cancellationToken);
            var result = rules.Select(r => new
            {
                id = r.Id,
                remoteAddress = r.RemoteAddress,
                action = r.Action.ToString(),
                status = r.Status.ToString(),
                policyId = r.PolicyId,
                policyName = r.Policy != null ? r.Policy.Name : null,
                alertId = r.AlertId,
                createdAt = r.CreatedAt,
                expiresAt = r.ExpiresAt
            });
            return Ok(result);
        }

        //POST /api/rules-set the new rule
        [HttpPost]
        public async Task<IActionResult> Create([FromBody] RuleApiDto dto, CancellationToken cancellationToken)
        {
            //add: Null check for dto, avoid NullReferenceException
            //Check whether the data sent from the front end is empty.
            if (dto == null)
                return BadRequest(new { error = "Request body is missing or invalid JSON." });

            //Check whether the target IP address has been filled in.
            if (string.IsNullOrWhiteSpace(dto.RemoteAddress))
                return BadRequest(new { error = "RemoteAddress is required." });

            //add: Manually parse enum strings, avoids deserialization errors
            //Convert the string “Block” into the enumeration value PolicyAction.block
            if (!Enum.TryParse<PolicyAction>(dto.Action, ignoreCase: true, out var action))
                return BadRequest(new { error = $"Invalid action:{dto.Action}" });

            //Convert the string “Active” into the enum value RuleStatus.Active
            if (!Enum.TryParse<RuleStatus>(dto.Status, ignoreCase: true, out var status))
                return BadRequest(new { error = $"Invalid status:{dto.Status}" });

            //Create a new Rule object using the data sent from the frontend.
            var rule = new Rule
            {
                //Generate unique rule ID
                Id = $"R-{DateTime.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid().ToString("N").Substring(0,4)}",
                //Rule name for Windows Firewall identification
                Name=$"PolarisSentinel_{action}_{dto.RemoteAddress}",

                RemoteAddress = dto.RemoteAddress,
                Action = action,
                Status = status,
                PolicyId = dto.PolicyId,
                ExpiresAt = dto.ExpiresAt,

                //IsBlockRule = true for Block action, false otherwise
                IsBlockRule=action==PolicyAction.Block,
                Enabled=true,
            };

            //Add the new rules to the database
            _uow.Rules.Add(rule);

            //Save to database
            await _uow.SaveChangesAsync(cancellationToken);

            //Return the ID of the new rule, and inform the frontend that “creation is successful”.
            return Ok(new { id = rule.Id });
        }

        //Put /api/rules/{id}-Edit rule
        [HttpPut("{id}")]
        public async Task<IActionResult> Update(string id, [FromBody] RuleApiDto dto, CancellationToken cancellationToken)
        {
            if (dto == null)
                return BadRequest(new { error = "Request body is missing or invalid JSON." });

            //Retrieve this rule from the database according to the ID
            var rule = await _uow.Rules.GetByIdAsync(id, cancellationToken);
            if (rule == null) return NotFound();

            if (!Enum.TryParse<PolicyAction>(dto.Action, ignoreCase: true, out var action))
                return BadRequest(new { error = $"Invalid action:{dto.Action}" });

            if (!Enum.TryParse<RuleStatus>(dto.Status, ignoreCase: true, out var status))
                return BadRequest(new { error = $"Invalid status:{dto.Status}" });

            rule.RemoteAddress = dto.RemoteAddress;
            rule.Action = action;
            rule.Status = status;
            rule.PolicyId = dto.PolicyId;
            rule.ExpiresAt = dto.ExpiresAt;

            _uow.Rules.Update(rule);
            await _uow.SaveChangesAsync(cancellationToken);
            return Ok(new { ok = true });
        }

        //Delete/api/rule/{id}
        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(string id, CancellationToken cancellationToken)
        {
            var rule = await _uow.Rules.GetByIdAsync(id, cancellationToken);
            if (rule == null) return NotFound();

            _uow.Rules.Remove(rule);
            await _uow.SaveChangesAsync(cancellationToken);
            return Ok(new { ok = true });
        }
    }
    // Use a string to connect action/status, Prevent incorrect data transmission, which causes the request to fail directly
    public class RuleApiDto
    {
        public string RemoteAddress { get; set; } = string.Empty;
        public string Action { get; set; } = "Monitor";
        public string Status { get; set; } = "Active";
        public string? PolicyId { get; set; }
        public DateTime? ExpiresAt { get; set; }
    }
 
}

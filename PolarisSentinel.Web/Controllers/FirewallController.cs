using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Core.Interfaces;

namespace PolarisSentinel.Web.Controllers
{
    // 防火墙规则查询与回滚 API
    // Firewall rule query and rollback API
    [Authorize]
    [ApiController]
    [Route("api/firewall")]
    public class FirewallController : ControllerBase
    {
        private readonly IFirewallEnforcer _firewall;

        public FirewallController(IFirewallEnforcer firewall)
        {
            _firewall = firewall;
        }

        [HttpGet("rules")]
        public IActionResult GetRules()
        {
            return Ok(_firewall.GetAllRules());
        }

        // 沿用登录/退出表单的防伪校验
        // Use the same antiforgery check as the login/logout forms
        [HttpPost("rollback")]
        [ValidateAntiForgeryToken]
        public IActionResult Rollback()
        {
            int removed = _firewall.RemoveAllManagedRules();
            return Ok(new { removed });
        }
    }
}

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace PolarisSentinel.Web.Controllers
{
    [Authorize]
    public class TrafficMonitorController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}

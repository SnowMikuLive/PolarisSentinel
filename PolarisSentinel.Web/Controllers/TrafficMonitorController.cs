using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace PolarisSentinel.Web.Controllers
{
    //Traffic Monitor controller
    [Authorize]
    public class TrafficMonitorController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}

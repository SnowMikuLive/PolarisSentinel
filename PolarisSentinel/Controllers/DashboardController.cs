using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace PolarisSentinel.Web.Controllers
{
    //Authorize attribute ensures that only authenticated users can access the dashboard
    [Authorize]
    public class DashboardController : Controller
    {
        public IActionResult Index()
        {
            //Static mock data is shown now as a placeholder, the real data will be pushed later.
            ViewBag.LiveTraffic = "0 Kpps";
            ViewBag.AlertsCount = 0;
            ViewBag.AiAccuracy = "-";
            ViewBag.ActiveRules = 0;
            return View();
        }
    }
}

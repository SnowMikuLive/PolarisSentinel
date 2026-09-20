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
            // Real data is pushed via SignalR.
            return View();
        }
    }
}

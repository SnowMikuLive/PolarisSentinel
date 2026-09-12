using Microsoft.AspNetCore.Mvc;

namespace PolarisSentinel.Web.Service
{
    public class DetectionStateService : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}

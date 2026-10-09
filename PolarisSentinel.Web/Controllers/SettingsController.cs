using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace PolarisSentinel.Web.Controllers
{
    [Authorize]
    public class SettingsController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace PolarisSentinel.Web.Controllers
{
    //AI Inference Engine controller
    [Authorize]
    public class AIEngineController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}

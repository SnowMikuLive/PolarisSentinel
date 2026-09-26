using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Interfaces;

namespace PolarisSentinel.Web.Controllers
{
    // Inference results page: the AI inference results that produced an alert.
    // Only non-benign detections are stored, so every row here is a real alert.
    [Authorize]
    public class InferenceResultsController : Controller
    {
        private readonly IUnitOfWork _uow;

        public InferenceResultsController(IUnitOfWork uow)
        {
            _uow = uow;
        }

        public async Task<IActionResult> Index(CancellationToken cancellationToken)
        {
            var alerts = await _uow.Alerts.GetAllAsync(cancellationToken);
            return View(alerts);
        }

        // Alert details (drill-down from the Rules page).
        public async Task<IActionResult> Details(string? id, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            var alert = await _uow.Alerts.GetByIdAsync(id, cancellationToken);
            if (alert == null)
            {
                return NotFound();
            }

            return View(alert);
        }
    }
}

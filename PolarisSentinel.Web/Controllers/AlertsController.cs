using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Core.Interfaces;

namespace PolarisSentinel.Web.Controllers
{
    // 告警只读展示
    // Alert read-only views
    [Authorize]
    public class AlertsController : Controller
    {
        private readonly IUnitOfWork _uow;

        public AlertsController(IUnitOfWork uow)
        {
            _uow = uow;
        }

        // 列表
        // List
        public async Task<IActionResult> Index(CancellationToken cancellationToken)
        {
            var alerts = await _uow.Alerts.GetAllAsync(cancellationToken);
            return View(alerts);
        }

        // 详情
        // Details
        public async Task<IActionResult> Details(Guid? id, CancellationToken cancellationToken)
        {
            if (id == null)
            {
                return NotFound();
            }

            var alert = await _uow.Alerts.GetByIdAsync(id.Value, cancellationToken);
            if (alert == null)
            {
                return NotFound();
            }

            return View(alert);
        }
    }
}

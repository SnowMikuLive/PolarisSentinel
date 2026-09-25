using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Web.Service;

namespace PolarisSentinel.Web.Controllers
{
    //推理结果界面：模型状态、实时结果与已持久化的告警
    //Inference results page:model status,live results and persisted alerts
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

        //告警详情（从规则页跳转查看是哪次检测产生了规则）
        //Alert details (drill-down from the Rules page)
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

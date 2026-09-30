using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Interfaces;
using System.Globalization;
using System.Text;

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

        // 导出已保存的告警及关联规则，不执行防火墙操作。
        // Export saved alerts and linked rules without changing the firewall.
        [HttpGet]
        public async Task<IActionResult> Export(CancellationToken cancellationToken)
        {
            var alerts = await _uow.Alerts.GetAllAsync(cancellationToken);
            var rules = (await _uow.Rules.GetAllAsync(cancellationToken)).ToLookup(r => r.AlertId);
            var csv = new StringBuilder();
            csv.AppendLine("Id,CreatedAt,SourceIp,SourcePort,DestinationIp,DestinationPort,Protocol,AttackType,DetectionSource,Confidence,RuleNames,Actions,RuleStatuses,Description");
            foreach (var alert in alerts)
            {
                var linked = rules[alert.Id].ToList();
                string[] cells =
                {
                    alert.Id, alert.CreatedAt.ToString("O", CultureInfo.InvariantCulture),
                    alert.SourceIp, alert.SourcePort.ToString(CultureInfo.InvariantCulture),
                    alert.DestinationIp, alert.DestinationPort.ToString(CultureInfo.InvariantCulture),
                    alert.Protocol.ToString(CultureInfo.InvariantCulture), alert.AttackType,
                    alert.DetectionSource.ToString(),
                    alert.ConfidenceScore?.ToString("R", CultureInfo.InvariantCulture) ?? "",
                    string.Join("; ", linked.Select(r => r.Name)),
                    string.Join("; ", linked.Select(r => r.Action)),
                    string.Join("; ", linked.Select(r => r.Status)),
                    alert.Description ?? ""
                };
                csv.AppendLine(string.Join(",", cells.Select(CsvCell)));
            }

            // BOM 方便 Excel 识别中文。
            // The BOM lets Excel recognize UTF-8 text.
            var bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(csv.ToString())).ToArray();
            return File(bytes, "text/csv; charset=utf-8", $"alerts-{DateTime.Now:yyyyMMdd-HHmmss}.csv");
        }

        private static string CsvCell(string value)
        {
            // 文本不作为表格公式执行。
            // Keep text from being interpreted as spreadsheet formulas.
            var trimmed = value.TrimStart();
            if (trimmed.Length > 0 && "=+-@".Contains(trimmed[0])) value = "'" + value;
            return "\"" + value.Replace("\"", "\"\"") + "\"";
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

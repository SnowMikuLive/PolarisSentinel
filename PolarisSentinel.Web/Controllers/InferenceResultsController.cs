using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Interfaces;
using System.Globalization;
using System.Text;
using static PolarisSentinel.Web.Service.SearchFilter;

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

        public async Task<IActionResult> Index(string? search = null, string? attackType = null, CancellationToken cancellationToken = default)
        {
            var alerts = await _uow.Alerts.GetAllAsync(cancellationToken);

            if (!string.IsNullOrWhiteSpace(attackType))
            {
                alerts = alerts.Where(a => string.Equals(a.AttackType, attackType, StringComparison.OrdinalIgnoreCase)).ToList();
            }

            if (!string.IsNullOrWhiteSpace(search))
            {
                var term = search.Trim();
                alerts = alerts
                    .Where(a =>
                        Contains(a.Id, term) ||
                        Contains(a.SourceIp, term) ||
                        Contains(a.DestinationIp, term) ||
                        Contains(a.AttackType, term) ||
                        Contains(a.Description, term) ||
                        Contains(a.SourcePort.ToString(), term) ||
                        Contains(a.DestinationPort.ToString(), term))
                    .ToList();
            }

            var all = await _uow.Alerts.GetAllAsync(cancellationToken);
            ViewBag.AttackTypes = all
                .Select(a => a.AttackType)
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(t => t, StringComparer.OrdinalIgnoreCase)
                .ToList();
            ViewBag.Search = search;
            ViewBag.AttackType = attackType;

            return View(alerts);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemoveAll(CancellationToken cancellationToken)
        {
            int removed = await _uow.Alerts.RemoveAllAsync(cancellationToken);
            TempData["success"] = $"{removed} alert(s) removed.";
            return RedirectToAction(nameof(Index));
        }

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

            var bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(csv.ToString())).ToArray();
            return File(bytes, "text/csv; charset=utf-8", $"alerts-{DateTime.Now:yyyyMMdd-HHmmss}.csv");
        }

        private static string CsvCell(string value)
        {
            var trimmed = value.TrimStart();
            if (trimmed.Length > 0 && "=+-@".Contains(trimmed[0])) value = "'" + value;
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }

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

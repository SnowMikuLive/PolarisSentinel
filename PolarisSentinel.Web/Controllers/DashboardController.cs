using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Web.Service;

namespace PolarisSentinel.Web.Controllers
{
    [Authorize]
    public class DashboardController : Controller
    {
        private readonly DetectionStateService _state;
        private readonly ITrafficRecordRepository _trafficRecords;
        private readonly TrafficHistoryService _history;

        public DashboardController(DetectionStateService state, ITrafficRecordRepository trafficRecords, TrafficHistoryService history)
        {
            _state = state;
            _trafficRecords = trafficRecords;
            _history = history;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemoveAllLiveTraffic(CancellationToken cancellationToken)
        {
            _history.DiscardPending();
            _state.Clear();
            await _trafficRecords.DeleteAllAsync(cancellationToken);
            TempData["success"] = "Live traffic history removed.";
            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public IActionResult ExportLiveTraffic()
        {
            var records = _state.GetLiveRecords();

            var csv = new StringBuilder();
            csv.AppendLine("Time,AlertId,Verdict,SourceIp,SourcePort,DestinationIp,DestinationPort,AttackType,Confidence,Action,DetectionSource,RuleName,Reason");

            foreach (var r in records)
            {
                string[] cells =
                {
                    r.CreatedAt,
                    r.AlertId,
                    r.Verdict,
                    r.SourceIp,
                    r.SourcePort.ToString(CultureInfo.InvariantCulture),
                    r.DestinationIp,
                    r.DestinationPort.ToString(CultureInfo.InvariantCulture),
                    r.AttackType,
                    r.ConfidenceScore?.ToString("R", CultureInfo.InvariantCulture) ?? string.Empty,
                    r.Action,
                    r.Source,
                    r.RuleName ?? string.Empty,
                    r.DecisionText is { Length: > 0 } text ? text : r.Reason
                };
                csv.AppendLine(string.Join(",", cells.Select(CsvCell)));
            }

            var bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(csv.ToString())).ToArray();
            return File(bytes, "text/csv; charset=utf-8", $"live-traffic-{DateTime.Now:yyyyMMdd-HHmmss}.csv");
        }

        private static string CsvCell(string value)
        {
            var trimmed = value.TrimStart();
            if (trimmed.Length > 0 && "=+-@".Contains(trimmed[0]))
            {
                value = "'" + value;
            }
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }
    }
}

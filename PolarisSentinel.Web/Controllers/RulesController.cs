using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Controllers
{
    // Firewall rule CRUD. All persistence is delegated to the firewall module.
    [Authorize]
    public class RulesController : Controller
    {
        private readonly IFirewallEnforcer _firewall;
        private readonly IUnitOfWork _unitOfWork;

        public RulesController(IFirewallEnforcer firewall, IUnitOfWork unitOfWork)
        {
            _firewall = firewall;
            _unitOfWork = unitOfWork;
        }

        public IActionResult Index()
        {
            return View(_firewall.GetAllRules());
        }

        public IActionResult Details(string? id)
        {
            var rule = string.IsNullOrEmpty(id) ? null : _firewall.GetById(id);
            if (rule == null)
            {
                return NotFound();
            }

            return View(rule);
        }

        public IActionResult Create()
        {
            PopulateLists();
            return View(new Rule());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Create(
            [Bind("SourceIp,SourcePort,DestinationIp,DestinationPort,Protocol,Action,Status")]
            Rule rule,
            int? durationValue,
            string? durationUnit)
        {
            Validate(rule);

            if (!ModelState.IsValid)
            {
                PopulateLists();
                return View(rule);
            }

            // A manual rule has no alert behind it, so the decision carries a synthetic alert
            // with the 5-tuple the operator entered.
            var alert = BuildManualAlert(rule);
            var decision = new PolicyDecision { Alert = alert, Action = rule.Action };

            _firewall.Apply(decision, null, null, null, ResolveDuration(durationValue, durationUnit));
            _unitOfWork.SaveChangesAsync().GetAwaiter().GetResult();

            TempData["success"] = "Rule created.";
            return RedirectToAction(nameof(Index));
        }

        public IActionResult Edit(string? id)
        {
            var rule = string.IsNullOrEmpty(id) ? null : _firewall.GetById(id);
            if (rule == null)
            {
                return NotFound();
            }

            PopulateLists();
            return View(rule);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Edit(
            string id,
            [Bind("SourceIp,SourcePort,DestinationIp,DestinationPort,Protocol,Action,Status")]
            Rule rule,
            int? durationValue,
            string? durationUnit)
        {
            Validate(rule);

            if (!ModelState.IsValid)
            {
                rule.Id = id;
                PopulateLists();
                return View(rule);
            }

            var updated = _firewall.Update(
                id,
                rule.SourceIp ?? string.Empty,
                rule.SourcePort ?? 0,
                rule.DestinationIp ?? string.Empty,
                rule.DestinationPort ?? 0,
                rule.Protocol ?? 0,
                rule.Action,
                rule.Status,
                ResolveDuration(durationValue, durationUnit));

            if (updated == null)
            {
                return NotFound();
            }

            _unitOfWork.SaveChangesAsync().GetAwaiter().GetResult();

            TempData["success"] = "Rule updated.";
            return RedirectToAction(nameof(Index));
        }

        public IActionResult Delete(string? id)
        {
            var rule = string.IsNullOrEmpty(id) ? null : _firewall.GetById(id);
            if (rule == null)
            {
                return NotFound();
            }

            return View(rule);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public IActionResult DeleteConfirmed(string id)
        {
            _firewall.Remove(id);
            _unitOfWork.SaveChangesAsync().GetAwaiter().GetResult();
            TempData["success"] = "Rule removed.";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult RemoveAll()
        {
            int removed = _firewall.RemoveAll();
            _unitOfWork.SaveChangesAsync().GetAwaiter().GetResult();
            TempData["success"] = $"{removed} rule(s) removed.";
            return RedirectToAction(nameof(Index));
        }

        private void PopulateLists()
        {
            ViewBag.Actions = new SelectList(PolicyActions.Blocking);
            ViewBag.Statuses = new SelectList(Enum.GetValues<RuleStatus>());
        }

        private void Validate(Rule rule)
        {
            if (string.IsNullOrWhiteSpace(rule.SourceIp) && string.IsNullOrWhiteSpace(rule.DestinationIp))
            {
                ModelState.AddModelError(nameof(Rule.SourceIp), "Provide at least one address, or pick Any on both sides.");
            }

            ValidateAddress(nameof(Rule.SourceIp), rule.SourceIp);
            ValidateAddress(nameof(Rule.DestinationIp), rule.DestinationIp);

            // ICMP has no ports, so a port-based action cannot be expressed.
            bool portAction = rule.Action is PolicyAction.BlockInboundPort or PolicyAction.BlockOutboundPort;
            if (portAction && rule.Protocol == ProtocolNumbers.Icmp)
            {
                ModelState.AddModelError(nameof(Rule.Action), "Port actions are not valid for ICMP; use an IP action instead.");
            }
        }

        private void ValidateAddress(string field, string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            if (!System.Net.IPAddress.TryParse(value.Split('/')[0], out _))
            {
                ModelState.AddModelError(field, "Enter a valid IP address or CIDR.");
            }
        }

        // A synthetic alert carrying the operator's 5-tuple; it is never persisted.
        private static Alert BuildManualAlert(Rule rule) => new()
        {
            DetectionSource = DetectionSource.None,
            AttackType = AttackTypes.Benign,
            SourceIp = rule.SourceIp ?? string.Empty,
            SourcePort = rule.SourcePort ?? 0,
            DestinationIp = rule.DestinationIp ?? string.Empty,
            DestinationPort = rule.DestinationPort ?? 0,
            Protocol = rule.Protocol ?? 0
        };

        // Convert value + unit into a duration; default 60 minutes.
        private static TimeSpan ResolveDuration(int? value, string? unit)
        {
            if (!value.HasValue || value.Value <= 0)
            {
                return TimeSpan.FromMinutes(60);
            }

            return unit switch
            {
                "hours" => TimeSpan.FromHours(value.Value),
                "days" => TimeSpan.FromDays(value.Value),
                _ => TimeSpan.FromMinutes(value.Value)
            };
        }
    }
}

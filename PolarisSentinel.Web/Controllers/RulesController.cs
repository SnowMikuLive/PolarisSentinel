using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using PolarisSentinel.Application;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using static PolarisSentinel.Web.Service.SearchFilter;

namespace PolarisSentinel.Web.Controllers
{
    // Firewall rule CRUD. Persistence and domain validation are delegated to RuleManagementService.
    [Authorize]
    public class RulesController : Controller
    {
        private readonly IFirewallEnforcer _firewall;
        private readonly RuleManagementService _rules;

        public RulesController(IFirewallEnforcer firewall, RuleManagementService rules)
        {
            _firewall = firewall;
            _rules = rules;
        }

        public IActionResult Index(
            RuleStatus? status = null,
            byte? protocol = null,
            PolicyAction? action = null,
            string? search = null,
            string? sort = null)
        {
            var rules = _firewall.GetAllRules();

            if (status.HasValue)
            {
                rules = rules.Where(r => r.Status == status.Value).ToList();
            }

            if (protocol.HasValue)
            {
                rules = rules.Where(r => r.Protocol == protocol.Value).ToList();
            }

            if (action.HasValue)
            {
                rules = rules.Where(r => r.Action == action.Value).ToList();
            }

            if (!string.IsNullOrWhiteSpace(search))
            {
                var term = search.Trim();
                rules = rules.Where(r =>
                    Contains(r.Id, term) ||
                    Contains(r.Name, term) ||
                    Contains(r.BlockedIp, term) ||
                    Contains(r.SourceIp, term) ||
                    Contains(r.DestinationIp, term) ||
                    Contains(r.PolicyId, term) ||
                    Contains(r.AlertId, term) ||
                    (r.BlockedPort is { } port && port.ToString().Contains(term, StringComparison.OrdinalIgnoreCase)))
                    .ToList();
            }

            rules = sort switch
            {
                "expires" => rules.OrderBy(r => r.ExpiresAt ?? DateTime.MaxValue).ToList(),
                "status" => rules.OrderBy(r => r.Status).ThenByDescending(r => r.CreatedAt).ToList(),
                "blocked" => rules.OrderBy(r => r.BlockedIp ?? r.BlockedPort?.ToString()).ToList(),
                "created" => rules.OrderByDescending(r => r.CreatedAt).ToList(),
                _ => rules.OrderByDescending(r => r.CreatedAt).ToList()
            };

            ViewBag.StatusList = new SelectList(
                Enum.GetValues<RuleStatus>().Select(v => new { Value = v.ToString(), Text = v.ToString() }),
                "Value", "Text", status?.ToString());
            ViewBag.ProtocolList = new SelectList(
                new[]
                {
                    new { Value = "6", Text = "TCP" },
                    new { Value = "17", Text = "UDP" },
                    new { Value = "1", Text = "ICMP" }
                },
                "Value", "Text", protocol?.ToString());
            ViewBag.ActionList = new SelectList(
                PolicyActions.Blocking.Select(v => new { Value = v.ToString(), Text = v.ToString() }),
                "Value", "Text", action?.ToString());

            ViewBag.Search = search;
            ViewBag.Sort = sort;

            return View(rules);
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

        public IActionResult Create(
            string? alertId = null,
            string? policyId = null,
            string? sourceIp = null,
            int? sourcePort = null,
            string? destinationIp = null,
            int? destinationPort = null,
            byte? protocol = null,
            PolicyAction? action = null)
        {
            PopulateLists();
            ViewBag.AlertId = alertId;
            ViewBag.PolicyId = policyId;
            var rule = new Rule
            {
                SourceIp = sourceIp ?? string.Empty,
                SourcePort = sourcePort,
                DestinationIp = destinationIp ?? string.Empty,
                DestinationPort = destinationPort,
                Protocol = protocol,
                Action = action ?? PolicyAction.BlockInboundIp,
                Status = RuleStatus.Active
            };
            return View(rule);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Create(
            [Bind("SourceIp,SourcePort,DestinationIp,DestinationPort,Protocol,Action,Status")]
            Rule rule,
            int? durationValue,
            string? durationUnit,
            string? alertId = null,
            string? policyId = null)
        {
            AddValidationErrors(rule);

            if (!ModelState.IsValid)
            {
                PopulateLists();
                ViewBag.AlertId = alertId;
                ViewBag.PolicyId = policyId;
                return View(rule);
            }

            _rules.Create(rule, alertId, policyId, durationValue, durationUnit);

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
            AddValidationErrors(rule);

            if (!ModelState.IsValid)
            {
                rule.Id = id;
                PopulateLists();
                return View(rule);
            }

            var updated = _rules.Update(rule, durationValue, durationUnit);

            if (updated == null)
            {
                return NotFound();
            }

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
            _rules.Remove(id);
            TempData["success"] = "Rule removed.";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult RemoveAll()
        {
            int removed = _rules.RemoveAll();
            TempData["success"] = $"{removed} rule(s) removed.";
            return RedirectToAction(nameof(Index));
        }

        private void PopulateLists()
        {
            ViewBag.Actions = new SelectList(PolicyActions.Blocking);
            ViewBag.Statuses = new SelectList(Enum.GetValues<RuleStatus>());
        }

        private void AddValidationErrors(Rule rule)
        {
            foreach (var (field, message) in _rules.Validate(rule))
            {
                ModelState.AddModelError(field, message);
            }
        }
    }
}

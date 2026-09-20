using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Controllers
{
    // 规则 CRUD 界面
    // Rule CRUD pages
    [Authorize]
    public class RulesController : Controller
    {
        private readonly IUnitOfWork _uow;

        public RulesController(IUnitOfWork uow)
        {
            _uow = uow;
        }

        //Change: the Index now transform the policy list and enums to the view for modal dropdowns
        // 列表
        // List
        public async Task<IActionResult> Index(CancellationToken cancellationToken)
        {
            var policies = await _uow.Policies.GetAllAsync(cancellationToken);
            ViewBag.Policies = policies.Select(p => new { p.Id, p.Name }).ToList();

            //Drop-down options for fronted rendering

            ViewBag.Actions = Enum.GetNames<PolicyAction>();
            ViewBag.Statuses = Enum.GetNames<RuleStatus>();

            //change: do not return rules, the frontend uses AJAX
            return View();
        }

        // 详情
        // Details
        public async Task<IActionResult> Details(Guid? id, CancellationToken cancellationToken)
        {
            if (id == null) return NotFound();
            var rule = await _uow.Rules.GetByIdAsync(id.Value, cancellationToken);
            if (rule == null) return NotFound();
            return View(rule);
        }

        // 新建表单
        // Create form
        public async Task<IActionResult> Create(CancellationToken cancellationToken)
        {
            await PopulateListsAsync(cancellationToken);
            return View(new Rule { RemoteAddress = string.Empty });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(
            [Bind("PolicyId,AlertId,Action,RemoteAddress,Status,ExpiresAt")]
            Rule rule,
            CancellationToken cancellationToken)
        {
            if (!ModelState.IsValid)
            {
                await PopulateListsAsync(cancellationToken);
                return View(rule);
            }

            _uow.Rules.Add(rule);
            await _uow.SaveChangesAsync(cancellationToken);
            TempData["success"] = "Rule created.";
            return RedirectToAction(nameof(Index));
        }

        // 编辑表单
        // Edit form
        public async Task<IActionResult> Edit(Guid? id, CancellationToken cancellationToken)
        {
            if (id == null)
            {
                return NotFound();
            }

            var rule = await _uow.Rules.GetByIdAsync(id.Value, cancellationToken);
            if (rule == null)
            {
                return NotFound();
            }

            await PopulateListsAsync(cancellationToken);
            return View(rule);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(
            Guid id,
            [Bind("Id,PolicyId,AlertId,Action,RemoteAddress,Status,ExpiresAt")]
            Rule rule,
            CancellationToken cancellationToken)
        {
            if (id != rule.Id)
            {
                return NotFound();
            }

            if (!ModelState.IsValid)
            {
                await PopulateListsAsync(cancellationToken);
                return View(rule);
            }

            _uow.Rules.Update(rule);
            await _uow.SaveChangesAsync(cancellationToken);
            TempData["success"] = "Rule updated.";
            return RedirectToAction(nameof(Index));
        }

        // 删除确认
        // Delete confirmation
        public async Task<IActionResult> Delete(Guid? id, CancellationToken cancellationToken)
        {
            if (id == null)
            {
                return NotFound();
            }

            var rule = await _uow.Rules.GetByIdAsync(id.Value, cancellationToken);
            if (rule == null)
            {
                return NotFound();
            }

            return View(rule);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(Guid id, CancellationToken cancellationToken)
        {
            var rule = await _uow.Rules.GetByIdAsync(id, cancellationToken);
            if (rule != null)
            {
                _uow.Rules.Remove(rule);
                await _uow.SaveChangesAsync(cancellationToken);
                TempData["success"] = "Rule deleted.";
            }

            return RedirectToAction(nameof(Index));
        }

        //Populate ViewBag dropdown lists for Create / Edit form pages
        private async Task PopulateListsAsync(CancellationToken cancellationToken)
        {
            var policies = await _uow.Policies.GetAllAsync(cancellationToken);
            ViewBag.Policies = new SelectList(policies, "Id", "Name");
            ViewBag.Actions = new SelectList(Enum.GetValues<PolicyAction>());
            ViewBag.Statuses = new SelectList(Enum.GetValues<RuleStatus>());
        }

        //add: JSON API for modal AJAX calls on the fronted
        //add: Get all rules
        //        [HttpGet("/api/rules")]
        //        public async Task<IActionResult> GetAllApi(CancellationToken cancellationToken)
        //        {
        //            var rules = await _uow.Rules.GetAllAsync(cancellationToken);

        //            //Only return fields needed by fronted
        //            var result = rules.Select(r => new 
        //            {
        //                id=r.Id,
        //                remoteAddress=r.RemoteAddress,
        //                action=r.Action.ToString(),
        //                status=r.Status.ToString(),
        //                policyId=r.PolicyId,
        //                //Null guard, avoid the problem when r.Policy is null
        //                policyName=r.Policy!=null?r.Policy.Name:null,
        //                alertId=r.AlertId,
        //                createdAt=r.CreatedAt,
        //                expiresAt=r.ExpiresAt
        //            });
        //            return Json(result);
        //        }

        //    //added: Create rule
        //    [HttpPost("/api/rules")]
        //        public async Task<IActionResult> CreateApi([FromBody] RuleApiDto dto, CancellationToken cancellationToken)
        //        {
        //            if (string.IsNullOrWhiteSpace(dto.RemoteAddress))
        //                return BadRequest(new { error = "RemoteAddress is required." });

        //            var rule = new Rule
        //            {
        //                RemoteAddress = dto.RemoteAddress,
        //                Action=dto.Action,
        //                Status=dto.Status,
        //                PolicyId=dto.PolicyId,
        //                ExpiresAt=dto.ExpiresAt,
        //            };
        //            _uow.Rules.Add(rule);
        //            await _uow.SaveChangesAsync(cancellationToken);
        //            return Json(new { id = rule.Id });
        //        }

        //        //add: Updated rule
        //        [HttpPut("/api/rules/{id}")]
        //        public async Task<IActionResult> UpdateApi(Guid id, [FromBody] RuleApiDto dto, CancellationToken cancellationToken)
        //        {
        //            var rule = await _uow.Rules.GetByIdAsync(id, cancellationToken);
        //            if (rule == null) return NotFound();

        //            rule.RemoteAddress = dto.RemoteAddress;
        //            rule.Action = dto.Action;
        //            rule.Status = dto.Status;
        //            rule.PolicyId = dto.PolicyId;
        //            rule.ExpiresAt = dto.ExpiresAt;

        //            _uow.Rules.Update(rule);
        //            await _uow.SaveChangesAsync(cancellationToken);
        //            return Json(new { ok = true });
        //        }

        //        //add:Delete rule
        //        [HttpDelete("/spi/rules/{id}")]
        //        public async Task<IActionResult> DeleteApi(Guid id, CancellationToken cancellationToken)
        //        {
        //            var rule = await _uow.Rules.GetByIdAsync(id, cancellationToken);
        //            if (rule == null) return NotFound();

        //            _uow.Rules.Remove(rule);
        //            await _uow.SaveChangesAsync(cancellationToken);
        //            return Json(new { ok = true });
        //        }

        //        private async Task PopulateListsAsync(CancellationToken cancellationToken)
        //        {
        //            var policies = await _uow.Policies.GetAllAsync(cancellationToken);
        //            ViewBag.Policies = new SelectList(policies, "Id", "Name");
        //            ViewBag.Actions = new SelectList(Enum.GetValues<PolicyAction>());
        //            ViewBag.Statuses = new SelectList(Enum.GetValues<RuleStatus>());
        //        }

        //    //added:API input DTO
        //    public class RuleApiDto
        //    {
        //    public string RemoteAddress { get; set; } = string.Empty;
        //    public PolicyAction Action { get; set; } = PolicyAction.Monitor;
        //    public RuleStatus Status { get; set; } = RuleStatus.Active;
        //    public Guid? PolicyId { get; set; }
        //    public DateTime? ExpiresAt { get; set; }

        //    }
    }
}

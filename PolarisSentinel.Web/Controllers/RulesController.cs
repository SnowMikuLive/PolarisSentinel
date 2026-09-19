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

        // 列表
        // List
        public async Task<IActionResult> Index(CancellationToken cancellationToken)
        {
            var rules = await _uow.Rules.GetAllAsync(cancellationToken);
            return View(rules);
        }

        // 详情
        // Details
        public async Task<IActionResult> Details(Guid? id, CancellationToken cancellationToken)
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

        private async Task PopulateListsAsync(CancellationToken cancellationToken)
        {
            var policies = await _uow.Policies.GetAllAsync(cancellationToken);
            ViewBag.Policies = new SelectList(policies, "Id", "Name");
            ViewBag.Actions = new SelectList(Enum.GetValues<PolicyAction>());
            ViewBag.Statuses = new SelectList(Enum.GetValues<RuleStatus>());
        }
    }
}

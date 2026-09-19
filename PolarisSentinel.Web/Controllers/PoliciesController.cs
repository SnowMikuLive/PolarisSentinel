using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Controllers
{
    // 策略 CRUD 界面
    // Policy CRUD pages
    [Authorize]
    public class PoliciesController : Controller
    {
        private readonly IUnitOfWork _uow;

        public PoliciesController(IUnitOfWork uow)
        {
            _uow = uow;
        }

        // 列表
        // List
        public async Task<IActionResult> Index(CancellationToken cancellationToken)
        {
            var policies = await _uow.Policies.GetAllAsync(cancellationToken);
            return View(policies);
        }

        // 详情
        // Details
        public async Task<IActionResult> Details(Guid? id, CancellationToken cancellationToken)
        {
            if (id == null)
            {
                return NotFound();
            }

            var policy = await _uow.Policies.GetByIdAsync(id.Value, cancellationToken);
            if (policy == null)
            {
                return NotFound();
            }

            return View(policy);
        }

        // 新建表单
        // Create form
        public IActionResult Create()
        {
            PopulateActions();
            return View(new Policy { Name = string.Empty });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(
            [Bind("Name,UserId,Action,RfConfidenceThreshold,AutoBlockConfidenceThreshold,BlockDurationMinutes,DecisionCooldownSeconds,IsActive")]
            Policy policy,
            CancellationToken cancellationToken)
        {
            if (!ModelState.IsValid)
            {
                PopulateActions();
                return View(policy);
            }

            _uow.Policies.Add(policy);
            await _uow.SaveChangesAsync(cancellationToken);
            TempData["success"] = "Policy created.";
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

            var policy = await _uow.Policies.GetByIdAsync(id.Value, cancellationToken);
            if (policy == null)
            {
                return NotFound();
            }

            PopulateActions();
            return View(policy);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(
            Guid id,
            [Bind("Id,Name,UserId,Action,RfConfidenceThreshold,AutoBlockConfidenceThreshold,BlockDurationMinutes,DecisionCooldownSeconds,IsActive")]
            Policy policy,
            CancellationToken cancellationToken)
        {
            if (id != policy.Id)
            {
                return NotFound();
            }

            if (!ModelState.IsValid)
            {
                PopulateActions();
                return View(policy);
            }

            _uow.Policies.Update(policy);
            await _uow.SaveChangesAsync(cancellationToken);
            TempData["success"] = "Policy updated.";
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

            var policy = await _uow.Policies.GetByIdAsync(id.Value, cancellationToken);
            if (policy == null)
            {
                return NotFound();
            }

            return View(policy);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(Guid id, CancellationToken cancellationToken)
        {
            var policy = await _uow.Policies.GetByIdAsync(id, cancellationToken);
            if (policy != null)
            {
                _uow.Policies.Remove(policy);
                await _uow.SaveChangesAsync(cancellationToken);
                TempData["success"] = "Policy deleted.";
            }

            return RedirectToAction(nameof(Index));
        }

        private void PopulateActions()
        {
            ViewBag.Actions = new SelectList(Enum.GetValues<PolicyAction>());
        }
    }
}

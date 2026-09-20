using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using PolarisSentinel.Core.Constants;
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
        private readonly UserManager<IdentityUser> _userManager;

        public PoliciesController(IUnitOfWork uow, UserManager<IdentityUser> userManager)
        {
            _uow = uow;
            _userManager = userManager;
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
        public async Task<IActionResult> Details(string? id, CancellationToken cancellationToken)
        {
            if (id == null)
            {
                return NotFound();
            }

            var policy = await _uow.Policies.GetByIdAsync(id, cancellationToken);
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
            PopulateLists();
            return View(new Policy { Name = string.Empty });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(
            [Bind("Name,Description,DetectionSource,Action,RfConfidenceThreshold,AutoBlockConfidenceThreshold,BlockDurationMinutes,DecisionCooldownSeconds,IsActive")]
            Policy policy,
            CancellationToken cancellationToken)
        {
            if (!ModelState.IsValid)
            {
                PopulateLists();
                return View(policy);
            }

            // 所有者固定为当前登录用户
            // Owner is always the signed-in user
            policy.UserId = _userManager.GetUserName(User) ?? string.Empty;
            policy.Id = await NextPolicyIdAsync(cancellationToken);
            _uow.Policies.Add(policy);
            await _uow.SaveChangesAsync(cancellationToken);
            TempData["success"] = "Policy created.";
            return RedirectToAction(nameof(Index));
        }

        // 编辑表单
        // Edit form
        public async Task<IActionResult> Edit(string? id, CancellationToken cancellationToken)
        {
            if (id == null)
            {
                return NotFound();
            }

            var policy = await _uow.Policies.GetByIdAsync(id, cancellationToken);
            if (policy == null)
            {
                return NotFound();
            }

            PopulateLists();
            return View(policy);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(
            string id,
            [Bind("Id,Name,Description,DetectionSource,Action,RfConfidenceThreshold,AutoBlockConfidenceThreshold,BlockDurationMinutes,DecisionCooldownSeconds,IsActive")]
            Policy policy,
            CancellationToken cancellationToken)
        {
            if (id != policy.Id)
            {
                return NotFound();
            }

            if (!ModelState.IsValid)
            {
                PopulateLists();
                return View(policy);
            }

            // 所有者不可编辑，保留原值
            // Owner is not editable; keep the stored value
            var existing = await _uow.Policies.GetByIdAsync(id, cancellationToken);
            policy.UserId = existing?.UserId ?? string.Empty;

            _uow.Policies.Update(policy);
            await _uow.SaveChangesAsync(cancellationToken);
            TempData["success"] = "Policy updated.";
            return RedirectToAction(nameof(Index));
        }

        // 删除确认
        // Delete confirmation
        public async Task<IActionResult> Delete(string? id, CancellationToken cancellationToken)
        {
            if (id == null)
            {
                return NotFound();
            }

            var policy = await _uow.Policies.GetByIdAsync(id, cancellationToken);
            if (policy == null)
            {
                return NotFound();
            }

            return View(policy);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id, CancellationToken cancellationToken)
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

        // 生成下一个 P-n 形式的策略 ID
        // Build the next "P-n" policy id
        private async Task<string> NextPolicyIdAsync(CancellationToken cancellationToken)
        {
            var policies = await _uow.Policies.GetAllAsync(cancellationToken);
            int max = 0;
            foreach (var p in policies)
            {
                if (p.Id.StartsWith(EntityIds.PolicyPrefix, StringComparison.Ordinal) &&
                    int.TryParse(p.Id.AsSpan(EntityIds.PolicyPrefix.Length), out int n) && n > max)
                {
                    max = n;
                }
            }
            return EntityIds.Policy(max + 1);
        }

        private void PopulateLists()
        {
            ViewBag.Actions = new SelectList(Enum.GetValues<PolicyAction>());
            ViewBag.DetectionSources = new SelectList(Enum.GetValues<DetectionSource>());
        }
    }
}

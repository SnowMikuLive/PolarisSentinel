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
    // Policy CRUD. UserId follows the signed-in user; every other property is editable.
    [Authorize]
    public class PoliciesController : Controller
    {
        private readonly IUnitOfWork _uow;
        private readonly PolicyManagementService _policies;

        public PoliciesController(IUnitOfWork uow, PolicyManagementService policies)
        {
            _uow = uow;
            _policies = policies;
        }

        public async Task<IActionResult> Index(string? search = null, string? sort = null, CancellationToken cancellationToken = default)
        {
            var policies = await _uow.Policies.GetAllAsync(cancellationToken);

            // Free-text search across the fields an operator scans by.
            if (!string.IsNullOrWhiteSpace(search))
            {
                var term = search.Trim();
                policies = policies
                    .Where(p =>
                        Contains(p.Id, term) ||
                        Contains(p.Name, term) ||
                        Contains(p.AttackType, term) ||
                        Contains(p.DetectionSource?.ToString(), term))
                    .ToList();
            }

            // Highest priority first by default: that is the order the engine evaluates them.
            policies = sort switch
            {
                "name" => policies.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList(),
                "action" => policies.OrderBy(p => p.Action).ThenByDescending(p => p.Priority).ToList(),
                "enabled" => policies.OrderByDescending(p => p.IsEnabled).ThenByDescending(p => p.Priority).ToList(),
                _ => policies.OrderByDescending(p => p.Priority).ThenBy(p => p.Id, StringComparer.Ordinal).ToList()
            };

            ViewBag.Search = search;
            ViewBag.Sort = sort;

            return View(policies);
        }

        // Quick enable/disable without opening the full edit form.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Toggle(string id, CancellationToken cancellationToken)
        {
            var policy = await FindAsync(id, cancellationToken);
            if (policy == null)
            {
                return NotFound();
            }

            policy.IsEnabled = !policy.IsEnabled;
            policy.UpdatedAt = DateTime.Now;
            _uow.Policies.Update(policy);
            await _uow.SaveChangesAsync(cancellationToken);

            TempData["success"] = $"Policy {policy.Id} {(policy.IsEnabled ? "enabled" : "disabled")}.";
            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Details(string? id, CancellationToken cancellationToken)
        {
            var policy = await FindAsync(id, cancellationToken);
            if (policy == null)
            {
                return NotFound();
            }

            return View(policy);
        }

        public IActionResult Create()
        {
            PopulateLists();
            return View(new Policy());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(
            [Bind("Name,Description,DetectionSource,RfThreshold,IfThreshold,AttackType,Action,BlockDurationMinutes,Priority,IsEnabled")]
            Policy policy,
            CancellationToken cancellationToken)
        {
            if (!Validate(policy))
            {
                PopulateLists();
                return View(policy);
            }

            policy.Id = await _policies.NextPolicyIdAsync(cancellationToken);
            policy.UserId = User.Identity?.Name ?? string.Empty;
            policy.CreatedAt = DateTime.Now;
            policy.UpdatedAt = DateTime.Now;

            _uow.Policies.Add(policy);
            await _uow.SaveChangesAsync(cancellationToken);

            TempData["success"] = "Policy created.";
            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Edit(string? id, CancellationToken cancellationToken)
        {
            var policy = await FindAsync(id, cancellationToken);
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
            [Bind("Name,Description,DetectionSource,RfThreshold,IfThreshold,AttackType,Action,BlockDurationMinutes,Priority,IsEnabled")]
            Policy policy,
            CancellationToken cancellationToken)
        {
            var existing = await FindAsync(id, cancellationToken);
            if (existing == null)
            {
                return NotFound();
            }

            if (!Validate(policy))
            {
                policy.Id = existing.Id;
                PopulateLists();
                return View(policy);
            }

            existing.Name = policy.Name;
            existing.Description = policy.Description;
            existing.DetectionSource = policy.DetectionSource;
            existing.RfThreshold = policy.RfThreshold;
            existing.IfThreshold = policy.IfThreshold;
            existing.AttackType = policy.AttackType;
            existing.Action = policy.Action;
            existing.BlockDurationMinutes = policy.BlockDurationMinutes;
            existing.Priority = policy.Priority;
            existing.IsEnabled = policy.IsEnabled;
            existing.UpdatedAt = DateTime.Now;

            _uow.Policies.Update(existing);
            await _uow.SaveChangesAsync(cancellationToken);

            TempData["success"] = "Policy updated.";
            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Delete(string? id, CancellationToken cancellationToken)
        {
            var policy = await FindAsync(id, cancellationToken);
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
            var policy = await FindAsync(id, cancellationToken);
            if (policy == null)
            {
                return NotFound();
            }

            _uow.Policies.Remove(policy);
            await _uow.SaveChangesAsync(cancellationToken);

            TempData["success"] = "Policy deleted.";
            return RedirectToAction(nameof(Index));
        }

        // Deletes every policy. Rules keep their PolicyId as a historical reference; the
        // FK is ON DELETE SET NULL, so those rules simply lose the link.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemoveAll(CancellationToken cancellationToken)
        {
            int removed = await _uow.Policies.RemoveAllAsync(cancellationToken);
            TempData["success"] = $"{removed} policy(ies) removed.";
            return RedirectToAction(nameof(Index));
        }

        private async Task<Policy?> FindAsync(string? id, CancellationToken cancellationToken)
        {
            return string.IsNullOrEmpty(id) ? null : await _uow.Policies.GetByIdAsync(id, cancellationToken);
        }

        private void PopulateLists()
        {
            ViewBag.DetectionSources = new SelectList(
                Enum.GetValues<DetectionSource>().Where(s => s != DetectionSource.None));
            ViewBag.Actions = new SelectList(PolicyActions.Blocking);
            ViewBag.AttackTypes = new SelectList(AttackTypes.Selectable);
        }

        // Surfaces the domain validation errors on ModelState for the form.
        private bool Validate(Policy policy)
        {
            foreach (var (field, message) in _policies.Validate(policy))
            {
                ModelState.AddModelError(field, message);
            }

            return ModelState.IsValid;
        }
    }
}

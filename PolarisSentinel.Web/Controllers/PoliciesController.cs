using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Controllers
{
    // Policy CRUD. UserId follows the signed-in user; every other property is editable.
    [Authorize]
    public class PoliciesController : Controller
    {
        private readonly IUnitOfWork _uow;

        public PoliciesController(IUnitOfWork uow)
        {
            _uow = uow;
        }

        public async Task<IActionResult> Index(CancellationToken cancellationToken)
        {
            var policies = await _uow.Policies.GetAllAsync(cancellationToken);
            return View(policies);
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

            policy.Id = await NextPolicyIdAsync(cancellationToken);
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

        // Validates the policy fields against the ranges the policy engine relies on.
        private bool Validate(Policy policy)
        {
            if (string.IsNullOrWhiteSpace(policy.Name))
            {
                ModelState.AddModelError(nameof(Policy.Name), "Name is required.");
            }

            if (policy.Priority is < 0 or > 100)
            {
                ModelState.AddModelError(nameof(Policy.Priority), "Priority must be between 0 and 100.");
            }

            if (policy.RfThreshold is { } rf && (rf < 0 || rf > 1))
            {
                ModelState.AddModelError(nameof(Policy.RfThreshold), "RF threshold must be between 0 and 1.");
            }

            if (policy.IfThreshold is { } ift && (ift < 0 || ift > 1))
            {
                ModelState.AddModelError(nameof(Policy.IfThreshold), "IF threshold must be between 0 and 1.");
            }

            if (PolicyActions.IsBlocking(policy.Action) && policy.BlockDurationMinutes <= 0)
            {
                ModelState.AddModelError(nameof(Policy.BlockDurationMinutes), "Block duration must be positive for blocking policies.");
            }

            if (!string.IsNullOrWhiteSpace(policy.AttackType) && !AttackTypes.IsDefined(policy.AttackType))
            {
                ModelState.AddModelError(nameof(Policy.AttackType), "Unknown attack type.");
            }

            return ModelState.IsValid;
        }

        // Next "P-n" id, scanned from the stored policies.
        private async Task<string> NextPolicyIdAsync(CancellationToken cancellationToken)
        {
            var policies = await _uow.Policies.GetAllAsync(cancellationToken);
            int max = 0;
            foreach (var p in policies)
            {
                if (p.Id.StartsWith("P-", StringComparison.Ordinal) &&
                    int.TryParse(p.Id.AsSpan(2), out int n) && n > max)
                {
                    max = n;
                }
            }
            return $"P-{max + 1}";
        }
    }
}

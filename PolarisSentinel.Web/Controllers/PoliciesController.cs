using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Controllers
{
    // Policy CRUD. Every property is editable except UserId, which follows the signed-in user.
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
            [Bind("DetectionSource,RfConfidenceThreshold,IfConfidenceThreshold,Action,BlockDurationMinutes,MatchAttackTypes,MatchProtocol,RuleSourceIpAction,RuleSourcePortAction,RuleDestinationIpAction,RuleDestinationPortAction")]
            Policy policy,
            CancellationToken cancellationToken)
        {
            if (!ModelState.IsValid)
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
            [Bind("DetectionSource,RfConfidenceThreshold,IfConfidenceThreshold,Action,BlockDurationMinutes,MatchAttackTypes,MatchProtocol,RuleSourceIpAction,RuleSourcePortAction,RuleDestinationIpAction,RuleDestinationPortAction")]
            Policy policy,
            CancellationToken cancellationToken)
        {
            var existing = await FindAsync(id, cancellationToken);
            if (existing == null)
            {
                return NotFound();
            }

            if (!ModelState.IsValid)
            {
                policy.Id = existing.Id;
                PopulateLists();
                return View(policy);
            }

            existing.DetectionSource = policy.DetectionSource;
            existing.RfConfidenceThreshold = policy.RfConfidenceThreshold;
            existing.IfConfidenceThreshold = policy.IfConfidenceThreshold;
            existing.BlockDurationMinutes = policy.BlockDurationMinutes;
            existing.MatchAttackTypes = policy.MatchAttackTypes;
            existing.MatchProtocol = policy.MatchProtocol;
            existing.RuleSourceIpAction = policy.RuleSourceIpAction;
            existing.RuleSourcePortAction = policy.RuleSourcePortAction;
            existing.RuleDestinationIpAction = policy.RuleDestinationIpAction;
            existing.RuleDestinationPortAction = policy.RuleDestinationPortAction;
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
            // Firewall rule actions are Allow or Block only; Monitor is a detection outcome.
            ViewBag.RuleActions = new SelectList(new[] { PolicyAction.Allow, PolicyAction.Block });
            // None is not a selectable detector.
            ViewBag.DetectionSources = new SelectList(
                Enum.GetValues<DetectionSource>().Where(s => s != DetectionSource.None));
            ViewBag.AttackTypes = new SelectList(AttackTypes.Selectable);
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

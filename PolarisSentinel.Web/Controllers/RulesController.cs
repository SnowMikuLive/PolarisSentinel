using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Controllers
{
    // 规则管理：只管理本系统创建的防火墙规则（PolarisSentinel_ 前缀）
    // Rule management for PolarisSentinel-created firewall rules only
    [Authorize]
    public class RulesController : Controller
    {
        private readonly IFirewallEnforcer _firewall;
        private readonly IUnitOfWork _uow;

        public RulesController(IFirewallEnforcer firewall, IUnitOfWork uow)
        {
            _firewall = firewall;
            _uow = uow;
        }

        // 列表：实时规则 + 审计信息（Policy/Alert 关联）
        // List: live rules enriched with audit links
        public async Task<IActionResult> Index(CancellationToken cancellationToken)
        {
            var live = _firewall.GetAllRules().ToList();
            var audit = await _uow.Rules.GetAllAsync(cancellationToken);

            // 以规则名匹配审计记录，补全 PolicyId / AlertId
            // Match audit rows by rule name to fill PolicyId / AlertId
            var byName = audit
                .Where(r => !string.IsNullOrEmpty(r.Name))
                .GroupBy(r => r.Name)
                .ToDictionary(g => g.Key, g => g.First());

            foreach (var rule in live)
            {
                if (byName.TryGetValue(rule.Name, out var row))
                {
                    rule.PolicyId = row.PolicyId;
                    rule.AlertId = row.AlertId;
                    rule.CreatedAt = row.CreatedAt;
                    rule.ExpiresAt = row.ExpiresAt;
                    rule.Status = row.Status;
                }
            }

            return View(live);
        }

        // 删除确认
        // Delete confirmation
        public IActionResult Delete(string? name)
        {
            if (string.IsNullOrEmpty(name))
            {
                return NotFound();
            }

            var rule = _firewall.GetAllRules().FirstOrDefault(r => r.Name == name);
            if (rule == null)
            {
                return NotFound();
            }

            return View(rule);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string name, CancellationToken cancellationToken)
        {
            _firewall.RemoveRule(name);

            // 同步移除审计记录
            // Remove the matching audit row
            var audit = await _uow.Rules.GetAllAsync(cancellationToken);
            var row = audit.FirstOrDefault(r => r.Name == name);
            if (row != null)
            {
                _uow.Rules.Remove(row);
                await _uow.SaveChangesAsync(cancellationToken);
            }

            TempData["success"] = "Rule removed.";
            return RedirectToAction(nameof(Index));
        }

        // 移除全部托管规则（回滚）
        // Remove all managed rules (rollback)
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemoveAll(CancellationToken cancellationToken)
        {
            int removed = _firewall.RemoveAllManagedRules();

            var audit = await _uow.Rules.GetAllAsync(cancellationToken);
            foreach (var row in audit)
            {
                _uow.Rules.Remove(row);
            }
            await _uow.SaveChangesAsync(cancellationToken);

            TempData["success"] = $"{removed} rule(s) removed.";
            return RedirectToAction(nameof(Index));
        }
    }
}

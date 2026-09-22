using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Web.Service;

namespace PolarisSentinel.Web.Controllers
{
    //规则管理：只管理本系统创建的防火墙规则（PolarisSentinel_前缀）
    //Rule management for PolarisSentinel-created firewall rules only
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

        //列表：实时规则+审计信息（Policy/Alert关联）
        //List:live rules enriched with audit links
        public async Task<IActionResult> Index(CancellationToken cancellationToken)
        {
            //Add: Set ViewBag for modal dropsowns of politicies in the + New Rule
            var policies = await _uow.Policies.GetAllAsync(cancellationToken);
            ViewBag.Policies = policies.Select(p => new { p.Id, p.Name }).ToList();

            var live = _firewall.GetAllRules().ToList();
            var audit = await _uow.Rules.GetAllAsync(cancellationToken);

            //以规则名匹配审计记录，补全PolicyId / AlertId
            //Match audit rows by rule name to fill PolicyId / AlertId
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
                    rule.Action = row.Action;
                    rule.AttackType = row.AttackType;
                }
            }

            return View(live);
        }

        //删除确认
        //Delete confirmation
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

            //同步移除审计记录
            //Remove the matching audit row
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

<<<<<<< HEAD
        //移除全部托管规则（回滚）
        //Remove all managed rules (rollback)
=======
        // 手动创建规则表单
        // Manual rule creation form
        public IActionResult Create()
        {
            PopulateLists();
            return View(new Rule { RemoteAddress = string.Empty });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(
            [Bind("RemoteAddress,Action,AttackType,Enabled")]
            Rule rule,
            string? cidrMode,
            int? cidrPrefix,
            int? durationValue,
            string? durationUnit,
            CancellationToken cancellationToken)
        {
            // CIDR 模式：拼接地址与前缀
            // CIDR mode: append the prefix to the address
            if (cidrMode == "cidr" && cidrPrefix.HasValue)
            {
                rule.RemoteAddress = $"{rule.RemoteAddress?.Trim()}/{cidrPrefix.Value}";
            }

            if (string.IsNullOrWhiteSpace(rule.RemoteAddress))
            {
                ModelState.AddModelError(nameof(Rule.RemoteAddress), "Remote address is required.");
            }

            if (!ModelState.IsValid)
            {
                PopulateLists();
                return View(rule);
            }

            // 手动规则使用 A-MANUAL-n 标识，保持托管规则命名
            // Manual rules use an A-MANUAL-n tag to keep the managed naming scheme
            var audit = await _uow.Rules.GetAllAsync(cancellationToken);
            int manualNumber = NextManualNumber(audit);
            string alertId = $"A-MANUAL-{manualNumber}";
            string ruleName = EntityIds.FirewallRule(alertId);

            TimeSpan duration = ResolveDuration(durationValue, durationUnit);

            // 手动规则同样需要一条告警记录，否则 Rule.AlertId 外键无父行
            // Manual rules also need an Alert row, otherwise the Rule.AlertId FK has no parent
            var decision = new Alert
            {
                Id = alertId,
                Action = rule.Action,
                SourceIp = rule.RemoteAddress,
                DestinationIp = string.Empty,
                AttackType = string.IsNullOrWhiteSpace(rule.AttackType) ? "Manual" : rule.AttackType,
                Confidence = 1f,
                Source = DetectionSource.None,
                DecidedAt = DateTime.UtcNow,
                Reason = "manual"
            };
            _uow.Alerts.Add(decision);

            // 仅 Block 动作会创建防火墙规则
            // Only a Block action creates a firewall rule
            if (rule.Action == PolicyAction.Block)
            {
                _firewall.BlockIp(decision, duration);
            }

            // 先落库告警，再写规则审计行，保证外键父行已存在
            // Save the alert first, then the rule audit row, so the FK parent exists
            await _uow.SaveChangesAsync(cancellationToken);

            _uow.Rules.Add(new Rule
            {
                Id = EntityIds.Rule(NextRuleNumber(audit)),
                Name = ruleName,
                PolicyId = null,
                AlertId = alertId,
                Action = rule.Action,
                RemoteAddress = rule.RemoteAddress,
                Enabled = rule.Enabled,
                AttackType = string.IsNullOrWhiteSpace(rule.AttackType) ? "Manual" : rule.AttackType,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.Add(duration)
            });
            await _uow.SaveChangesAsync(cancellationToken);

            TempData["success"] = "Rule created.";
            return RedirectToAction(nameof(Index));
        }

        // 编辑规则表单（PolicyId / AlertId 只读）
        // Edit form (PolicyId / AlertId are read-only)
        public IActionResult Edit(string? name)
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

            PopulateLists();
            return View(rule);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(
            string name,
            [Bind("RemoteAddress,Action,AttackType,Enabled")]
            Rule rule,
            string? cidrMode,
            int? cidrPrefix,
            int? durationValue,
            string? durationUnit,
            CancellationToken cancellationToken)
        {
            if (cidrMode == "cidr" && cidrPrefix.HasValue)
            {
                rule.RemoteAddress = $"{rule.RemoteAddress?.Trim()}/{cidrPrefix.Value}";
            }

            if (string.IsNullOrWhiteSpace(rule.RemoteAddress))
            {
                ModelState.AddModelError(nameof(Rule.RemoteAddress), "Remote address is required.");
            }

            if (!ModelState.IsValid)
            {
                rule.Name = name;
                PopulateLists();
                return View(rule);
            }

            // 先移除旧规则，再按新地址重建
            // Remove the old rule, then recreate with the new address
            _firewall.RemoveRule(name);

            var audit = await _uow.Rules.GetAllAsync(cancellationToken);
            var row = audit.FirstOrDefault(r => r.Name == name);
            string alertId = row?.AlertId ?? $"A-MANUAL-{NextManualNumber(audit)}";
            string newName = EntityIds.FirewallRule(alertId);

            TimeSpan duration = ResolveDuration(durationValue, durationUnit);

            var decision = new Alert
            {
                Id = alertId,
                Action = rule.Action,
                SourceIp = rule.RemoteAddress,
                DestinationIp = string.Empty,
                AttackType = string.IsNullOrWhiteSpace(rule.AttackType) ? "Manual" : rule.AttackType,
                Confidence = 1f,
                Source = DetectionSource.None,
                DecidedAt = DateTime.UtcNow,
                Reason = "manual"
            };

            // 审计行不存在时补建告警，避免外键悬空
            // Create the alert when no audit row exists, so the FK is never dangling
            if (row == null)
            {
                _uow.Alerts.Add(decision);
                await _uow.SaveChangesAsync(cancellationToken);
            }

            if (rule.Action == PolicyAction.Block)
            {
                _firewall.BlockIp(decision, duration);
            }

            if (row != null)
            {
                row.Name = newName;
                row.RemoteAddress = rule.RemoteAddress;
                row.Action = rule.Action;
                row.Enabled = rule.Enabled;
                row.AttackType = string.IsNullOrWhiteSpace(rule.AttackType) ? "Manual" : rule.AttackType;
                row.ExpiresAt = DateTime.UtcNow.Add(duration);
                _uow.Rules.Update(row);
                await _uow.SaveChangesAsync(cancellationToken);
            }

            TempData["success"] = "Rule updated.";
            return RedirectToAction(nameof(Index));
        }

        // 由数值 + 单位换算封禁时长，缺省 60 分钟
        // Convert value + unit into a duration; default 60 minutes
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

        // 移除全部托管规则（回滚）
        // Remove all managed rules (rollback)
>>>>>>> d47e7ec0c32803f010bc8a3c97a4dc42d392cd92
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

        // 下一个 R-n 审计编号
        // Next "R-n" audit number
        private static int NextRuleNumber(IReadOnlyList<Rule> rules)
        {
            int max = 0;
            foreach (var r in rules)
            {
                if (r.Id.StartsWith(EntityIds.RulePrefix, StringComparison.Ordinal) &&
                    int.TryParse(r.Id.AsSpan(EntityIds.RulePrefix.Length), out int n) && n > max)
                {
                    max = n;
                }
            }
            return max + 1;
        }

        // 下一个手动规则编号
        // Next manual rule number
        private static int NextManualNumber(IReadOnlyList<Rule> rules)
        {
            int max = 0;
            foreach (var r in rules)
            {
                if (r.AlertId != null && r.AlertId.StartsWith("A-MANUAL-", StringComparison.Ordinal) &&
                    int.TryParse(r.AlertId.AsSpan("A-MANUAL-".Length), out int n) && n > max)
                {
                    max = n;
                }
            }
            return max + 1;
        }

        private void PopulateLists()
        {
            ViewBag.Actions = new SelectList(Enum.GetValues<PolicyAction>());
            ViewBag.AttackTypes = new SelectList(new[]
            {
                AttackTypes.Benign,
                AttackTypes.DoS,
                AttackTypes.PortScan,
                AttackTypes.BruteForce,
                AttackTypes.UnknownAnomaly,
                "Manual"
            });
            ViewBag.EnabledOptions = new SelectList(new[]
            {
                new { Value = "true", Text = "Enabled" },
                new { Value = "false", Text = "Disabled" }
            }, "Value", "Text");
        }
    }
}

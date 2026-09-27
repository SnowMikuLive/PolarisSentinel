using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentienlUnitTestProject
{
    internal sealed class FakeRuleRepository : IRuleRepository
    {
        private readonly List<Rule> _rules = new();

        public void Add(Rule rule) => _rules.Add(rule);

        public Task<string> NextIdAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(EntityIds.Rule(EntityIds.MaxNumber(_rules.Select(r => r.Id), EntityIds.RulePrefix) + 1));

        public Task<IReadOnlyList<Rule>> GetActiveAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<Rule>>(_rules.Where(r => r.Status == RuleStatus.Active).ToList());

        public Task<IReadOnlyList<Rule>> GetAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<Rule>>(_rules.ToList());

        public Task<Rule?> GetByIdAsync(string id, CancellationToken cancellationToken = default) =>
            Task.FromResult(_rules.FirstOrDefault(r => r.Id == id));

        public void Update(Rule rule)
        {
            var index = _rules.FindIndex(r => r.Id == rule.Id);
            if (index >= 0)
            {
                _rules[index] = rule;
            }
        }

        public void Remove(Rule rule) => _rules.RemoveAll(r => r.Id == rule.Id);

        public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default) => Task.FromResult(1);
    }

    internal sealed class FakeAlertRepository : IAlertRepository
    {
        private readonly List<Alert> _alerts = new();

        public void Add(Alert alert) => _alerts.Add(alert);

        public Task<string> NextIdAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(EntityIds.Alert(EntityIds.MaxNumber(_alerts.Select(a => a.Id), EntityIds.AlertPrefix) + 1));

        public Task<IReadOnlyList<Alert>> GetRecentAsync(int count, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<Alert>>(_alerts.OrderByDescending(a => a.CreatedAt).Take(count).ToList());

        public Task<IReadOnlyList<Alert>> GetAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<Alert>>(_alerts.ToList());

        public Task<Alert?> GetByIdAsync(string id, CancellationToken cancellationToken = default) =>
            Task.FromResult(_alerts.FirstOrDefault(a => a.Id == id));
    }

    internal sealed class FakePolicyRepository : IPolicyRepository
    {
        private readonly List<Policy> _policies = new();

        public Task<Policy?> GetByIdAsync(string id, CancellationToken cancellationToken = default) =>
            Task.FromResult(_policies.FirstOrDefault(p => p.Id == id));

        public Task<IReadOnlyList<Policy>> GetAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<Policy>>(_policies.ToList());

        public Task<IReadOnlyList<Policy>> GetEnabledAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<Policy>>(_policies.Where(p => p.IsEnabled).ToList());

        public void Add(Policy policy) => _policies.Add(policy);

        public void Update(Policy policy)
        {
            var index = _policies.FindIndex(p => p.Id == policy.Id);
            if (index >= 0)
            {
                _policies[index] = policy;
            }
        }

        public void Remove(Policy policy) => _policies.RemoveAll(p => p.Id == policy.Id);
    }

    internal sealed class FakeUnitOfWork : IUnitOfWork
    {
        public IAlertRepository Alerts { get; } = new FakeAlertRepository();

        public IRuleRepository Rules { get; } = new FakeRuleRepository();

        public IPolicyRepository Policies { get; } = new FakePolicyRepository();

        public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default) => Task.FromResult(1);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

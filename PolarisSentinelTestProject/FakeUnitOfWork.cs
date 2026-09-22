using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentienlUnitTestProject
{
    // In-memory unit of work so pipeline tests do not need a database.
    public class FakeUnitOfWork : IUnitOfWork
    {
        public FakeUnitOfWork(IRuleRepository? rules = null, IAlertRepository? alerts = null)
        {
            Rules = rules ?? new FakeRuleRepository();
            Alerts = alerts ?? new FakeAlertRepository();
        }

        public IAlertRepository Alerts { get; }

        public IRuleRepository Rules { get; }

        public IPolicyRepository Policies { get; } = new FakePolicyRepository();

        public int SaveCount { get; private set; }

        public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            SaveCount++;
            return Task.FromResult(0);
        }

        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }
    }

    // In-memory alert repository; alerts are stored by reference.
    public class FakeAlertRepository : IAlertRepository
    {
        private readonly List<Alert> _alerts = new();

        public void Add(Alert alert)
        {
            _alerts.Add(alert);
        }

        public Task<IReadOnlyList<Alert>> GetRecentAsync(int count, CancellationToken cancellationToken = default)
        {
            IReadOnlyList<Alert> recent = _alerts.OrderByDescending(a => a.DetectedAt).Take(count).ToList();
            return Task.FromResult(recent);
        }

        public Task<IReadOnlyList<Alert>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            IReadOnlyList<Alert> all = _alerts.ToList();
            return Task.FromResult(all);
        }

        public Task<Alert?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_alerts.FirstOrDefault(a => a.Id == id));
        }
    }

    // In-memory policy repository; unused by the pipeline tests.
    public class FakePolicyRepository : IPolicyRepository
    {
        private readonly List<Policy> _policies = new();

        public void Add(Policy policy)
        {
            _policies.Add(policy);
        }

        public Task<IReadOnlyList<Policy>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            IReadOnlyList<Policy> all = _policies.ToList();
            return Task.FromResult(all);
        }

        public Task<Policy?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_policies.FirstOrDefault(p => p.Id == id));
        }

        public Task<Policy?> GetByUserAsync(string userId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_policies.FirstOrDefault(p => p.UserId == userId));
        }

        public void Update(Policy policy)
        {
        }

        public void Remove(Policy policy)
        {
            _policies.Remove(policy);
        }
    }
}

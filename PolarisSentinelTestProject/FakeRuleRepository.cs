using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentienlUnitTestProject
{
    // In-memory rule repository so firewall tests do not need a database.
    public class FakeRuleRepository : IRuleRepository
    {
        private readonly List<Rule> _rules = new();

        public void Add(Rule rule)
        {
            _rules.Add(rule);
        }

        public Task<IReadOnlyList<Rule>> GetActiveAsync(CancellationToken cancellationToken = default)
        {
            var now = DateTime.Now;
            IReadOnlyList<Rule> active = _rules.Where(r => r.ExpiresAt == null || r.ExpiresAt > now).ToList();
            return Task.FromResult(active);
        }

        public Task<IReadOnlyList<Rule>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            IReadOnlyList<Rule> all = _rules.OrderByDescending(r => r.CreatedAt).ToList();
            return Task.FromResult(all);
        }

        public Task<Rule?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_rules.FirstOrDefault(r => r.Id == id));
        }

        public void Update(Rule rule)
        {
            // Entities are stored by reference, so an in-place edit needs no work.
        }

        public void Remove(Rule rule)
        {
            _rules.Remove(rule);
        }

        public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }
    }
}

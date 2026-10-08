using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IRuleRepository
{
    void Add(Rule rule);

    // The next sequential rule id, e.g. "R-1".
    Task<string> NextIdAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Rule>> GetAllAsync(CancellationToken cancellationToken = default);

    Task<Rule?> GetByIdAsync(string id, CancellationToken cancellationToken = default);

    Task<Rule?> GetByNameAsync(string name, CancellationToken cancellationToken = default);

    void Update(Rule rule);

    void Remove(Rule rule);

    // Commit staged rule changes.
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}

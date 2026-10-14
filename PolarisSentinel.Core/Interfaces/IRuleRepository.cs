using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IRuleRepository
{
    void Add(Rule rule);

    Task<string> NextIdAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Rule>> GetAllAsync(CancellationToken cancellationToken = default);

    Task<Rule?> GetByIdAsync(string id, CancellationToken cancellationToken = default);

    Task<Rule?> GetByNameAsync(string name, CancellationToken cancellationToken = default);

    void Update(Rule rule);

    void Remove(Rule rule);

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}

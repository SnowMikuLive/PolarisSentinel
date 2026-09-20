using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IRuleRepository
{
    void Add(Rule rule);

    Task<IReadOnlyList<Rule>> GetActiveAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Rule>> GetAllAsync(CancellationToken cancellationToken = default);

    Task<Rule?> GetByIdAsync(string id, CancellationToken cancellationToken = default);

    void Update(Rule rule);

    void Remove(Rule rule);
}

using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IRuleRepository
{
    void Add(Rule rule);

    Task<IReadOnlyList<Rule>> GetActiveAsync(CancellationToken cancellationToken = default);
}

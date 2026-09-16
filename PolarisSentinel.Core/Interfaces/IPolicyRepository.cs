using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IPolicyRepository
{
    Task<Policy?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Policy>> GetByUserAsync(string userId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Policy>> GetAllAsync(CancellationToken cancellationToken = default);

    void Add(Policy policy);

    void Update(Policy policy);

    void Remove(Policy policy);
}

using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IPolicyRepository
{
    Task<Policy?> GetByIdAsync(string id, CancellationToken cancellationToken = default);

    // The policy owned by a user; null when the user has none yet.
    Task<Policy?> GetByUserAsync(string userId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Policy>> GetAllAsync(CancellationToken cancellationToken = default);

    void Add(Policy policy);

    void Update(Policy policy);

    void Remove(Policy policy);
}

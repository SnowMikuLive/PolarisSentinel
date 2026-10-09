using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IPolicyRepository
{
    Task<Policy?> GetByIdAsync(string id, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Policy>> GetAllAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Policy>> GetEnabledAsync(CancellationToken cancellationToken = default);

    void Add(Policy policy);

    void Update(Policy policy);

    void Remove(Policy policy);

    Task<int> RemoveAllAsync(CancellationToken cancellationToken = default);
}

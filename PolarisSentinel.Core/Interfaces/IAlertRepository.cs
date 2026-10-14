using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IAlertRepository
{
    void Add(Alert alert);

    Task<string> NextIdAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Alert>> GetAllAsync(CancellationToken cancellationToken = default);

    Task<Alert?> GetByIdAsync(string id, CancellationToken cancellationToken = default);

    Task<int> RemoveAllAsync(CancellationToken cancellationToken = default);
}

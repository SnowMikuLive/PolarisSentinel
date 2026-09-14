using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IAlertRepository
{
    Task AddAsync(Alert alert, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Alert>> GetRecentAsync(int count, CancellationToken cancellationToken = default);
}

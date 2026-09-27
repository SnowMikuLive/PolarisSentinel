using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IAlertRepository
{
    // Stages an alert; commit happens via IUnitOfWork.SaveChangesAsync.
    void Add(Alert alert);

    // The next sequential alert id, e.g. "A-1".
    Task<string> NextIdAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Alert>> GetRecentAsync(int count, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Alert>> GetAllAsync(CancellationToken cancellationToken = default);

    Task<Alert?> GetByIdAsync(string id, CancellationToken cancellationToken = default);
}

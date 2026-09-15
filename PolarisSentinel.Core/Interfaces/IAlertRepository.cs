using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IAlertRepository
{
    // Stages an alert; commit happens via IUnitOfWork.SaveChangesAsync.
    void Add(Alert alert);

    Task<IReadOnlyList<Alert>> GetRecentAsync(int count, CancellationToken cancellationToken = default);
}

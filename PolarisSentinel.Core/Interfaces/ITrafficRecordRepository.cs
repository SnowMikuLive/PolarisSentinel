using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface ITrafficRecordRepository
{
    void AddRange(IEnumerable<TrafficRecord> records);

    Task<IReadOnlyList<TrafficRecord>> GetSinceAsync(DateTime since, CancellationToken cancellationToken = default);

    Task<int> DeleteBeforeAsync(DateTime cutoff, CancellationToken cancellationToken = default);

    Task<int> DeleteAllAsync(CancellationToken cancellationToken = default);

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}

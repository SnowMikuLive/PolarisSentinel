using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface ITrafficRecordRepository
{
    void AddRange(IEnumerable<TrafficRecord> records);

    // Records created at or after the given local time, newest first.
    Task<IReadOnlyList<TrafficRecord>> GetSinceAsync(DateTime since, CancellationToken cancellationToken = default);

    // Deletes records older than the given local time.
    Task<int> DeleteBeforeAsync(DateTime cutoff, CancellationToken cancellationToken = default);

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}

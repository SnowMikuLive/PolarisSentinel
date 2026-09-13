using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Persistence contract for detection events (application layer boundary).
// Implemented in the infrastructure/persistence layer.
public interface IDetectionRepository
{
    Task AddAsync(DetectionEvent detectionEvent, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<DetectionEvent>> GetRecentAsync(int count, CancellationToken cancellationToken = default);
}

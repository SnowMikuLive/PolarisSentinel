using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// 检测事件持久化接口
// Persistence contract for detection events
public interface IDetectionRepository
{
    Task AddAsync(DetectionEvent detectionEvent, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<DetectionEvent>> GetRecentAsync(int count, CancellationToken cancellationToken = default);
}

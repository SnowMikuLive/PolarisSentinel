// Replaced by AlertRepository.
namespace PolarisSentinel.Data;
<<<<<<< HEAD

// 检测事件 EF Core 仓储
// EF Core implementation of the detection repository
public class DetectionRepository : IDetectionRepository
{
    private readonly SentinelDbContext _context;

    public DetectionRepository(SentinelDbContext context)
    {
        _context = context;
    }

    public async Task AddAsync(DetectionEvent detectionEvent, CancellationToken cancellationToken = default)
    {
        await _context.DetectionEvents.AddAsync(detectionEvent, cancellationToken);
        await _context.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<DetectionEvent>> GetRecentAsync(int count, CancellationToken cancellationToken = default)
    {
        return await _context.DetectionEvents
            .AsNoTracking()
            .OrderByDescending(e => e.DecidedAt)
            .Take(count)
            .ToListAsync(cancellationToken);
    }
}
=======
>>>>>>> a2e4aeebbed2da61e08be9661cc010e1a59515ad

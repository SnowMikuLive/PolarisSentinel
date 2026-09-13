using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Data;

// EF Core implementation of the detection repository.
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

using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Data;

public class AlertRepository : IAlertRepository
{
    private readonly SentinelDbContext _context;

    public AlertRepository(SentinelDbContext context)
    {
        _context = context;
    }

    public async Task AddAsync(Alert alert, CancellationToken cancellationToken = default)
    {
        await _context.Alerts.AddAsync(alert, cancellationToken);
        await _context.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Alert>> GetRecentAsync(int count, CancellationToken cancellationToken = default)
    {
        return await _context.Alerts
            .AsNoTracking()
            .OrderByDescending(a => a.DetectedAt)
            .Take(count)
            .ToListAsync(cancellationToken);
    }
}

using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.DataAccess.Data;

namespace PolarisSentinel.DataAccess.Repository;

public class AlertRepository : IAlertRepository
{
    private readonly SentinelDbContext _context;

    public AlertRepository(SentinelDbContext context)
    {
        _context = context;
    }

    public void Add(Alert alert)
    {
        _context.Alerts.Add(alert);
    }

    public async Task<IReadOnlyList<Alert>> GetRecentAsync(int count, CancellationToken cancellationToken = default)
    {
        return await _context.Alerts
            .AsNoTracking()
            .OrderByDescending(a => a.DetectedAt)
            .Take(count)
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Alert>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Alerts
            .AsNoTracking()
            .OrderByDescending(a => a.DetectedAt)
            .ToListAsync(cancellationToken);
    }

    public async Task<Alert?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await _context.Alerts
            .AsNoTracking()
            .FirstOrDefaultAsync(a => a.Id == id, cancellationToken);
    }
}

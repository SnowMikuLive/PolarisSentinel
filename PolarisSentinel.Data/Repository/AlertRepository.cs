using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Core.Constants;
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

    // Sequential ids are derived from the highest existing number, so deleted
    // rows can cause a number to be reused; acceptable for this prototype.
    public async Task<string> NextIdAsync(CancellationToken cancellationToken = default)
    {
        var ids = await _context.Alerts.Select(a => a.Id).ToListAsync(cancellationToken);
        return EntityIds.Next(ids, EntityIds.AlertPrefix, EntityIds.Alert);
    }

    public async Task<IReadOnlyList<Alert>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Alerts
            .AsNoTracking()
            .OrderByDescending(a => a.CreatedAt)
            .ToListAsync(cancellationToken);
    }

    public async Task<Alert?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
    {
        return await _context.Alerts
            .AsNoTracking()
            .FirstOrDefaultAsync(a => a.Id == id, cancellationToken);
    }
}

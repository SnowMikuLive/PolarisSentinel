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

    public async Task<string> NextIdAsync(CancellationToken cancellationToken = default)
    {
        int max = await _context.Database.SqlQuery<int>(
            $"SELECT ISNULL(MAX(TRY_CAST(SUBSTRING([Id], {EntityIds.AlertPrefix.Length + 1}, 20) AS INT)), 0) AS [Value] FROM [Alerts]")
            .SingleAsync(cancellationToken);
        return EntityIds.Alert(EntityIds.ReserveNextNumber(max, EntityIds.AlertPrefix));
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

    public async Task<int> RemoveAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Alerts.ExecuteDeleteAsync(cancellationToken);
    }
}
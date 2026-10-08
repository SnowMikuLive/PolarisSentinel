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

    // The next number comes from a single aggregate instead of loading every id: under a
    // flood the table grows fast and the old full-table read made each insert slower than the
    // last. TRY_CAST ignores any non-numeric ids.
    public async Task<string> NextIdAsync(CancellationToken cancellationToken = default)
    {
        int max = await _context.Database.SqlQuery<int>(
            $"SELECT ISNULL(MAX(TRY_CAST(SUBSTRING([Id], {EntityIds.AlertPrefix.Length + 1}, 20) AS INT)), 0) AS [Value] FROM [Alerts]")
            .SingleAsync(cancellationToken);
        return EntityIds.Alert(max + 1);
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
        // A set-based delete avoids loading every row just to remove it.
        return await _context.Alerts.ExecuteDeleteAsync(cancellationToken);
    }
}

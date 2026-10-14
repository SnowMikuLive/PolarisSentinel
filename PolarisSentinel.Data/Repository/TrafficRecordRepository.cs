using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.DataAccess.Data;

namespace PolarisSentinel.DataAccess.Repository;

public class TrafficRecordRepository : ITrafficRecordRepository
{
    private readonly SentinelDbContext _context;

    public TrafficRecordRepository(SentinelDbContext context)
    {
        _context = context;
    }

    public void AddRange(IEnumerable<TrafficRecord> records)
    {
        _context.TrafficRecords.AddRange(records);
    }

    public async Task<IReadOnlyList<TrafficRecord>> GetSinceAsync(DateTime since, CancellationToken cancellationToken = default)
    {
        return await _context.TrafficRecords
            .AsNoTracking()
            .Where(r => r.CreatedAt >= since)
            .OrderByDescending(r => r.CreatedAt)
            .ToListAsync(cancellationToken);
    }

    public async Task<int> DeleteBeforeAsync(DateTime cutoff, CancellationToken cancellationToken = default)
    {
        return await _context.TrafficRecords
            .Where(r => r.CreatedAt < cutoff)
            .ExecuteDeleteAsync(cancellationToken);
    }

    public async Task<int> DeleteAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.TrafficRecords.ExecuteDeleteAsync(cancellationToken);
    }

    public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return _context.SaveChangesAsync(cancellationToken);
    }
}

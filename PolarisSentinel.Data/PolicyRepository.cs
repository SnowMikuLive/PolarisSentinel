using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Data;

public class PolicyRepository : IPolicyRepository
{
    private readonly SentinelDbContext _context;

    public PolicyRepository(SentinelDbContext context)
    {
        _context = context;
    }

    public async Task<Policy?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await _context.Policies
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == id, cancellationToken);
    }

    public async Task<IReadOnlyList<Policy>> GetByUserAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await _context.Policies
            .AsNoTracking()
            .Where(p => p.UserId == userId)
            .ToListAsync(cancellationToken);
    }
}

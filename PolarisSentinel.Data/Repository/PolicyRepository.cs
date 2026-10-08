using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.DataAccess.Data;

namespace PolarisSentinel.DataAccess.Repository;

public class PolicyRepository : IPolicyRepository
{
    private readonly SentinelDbContext _context;

    public PolicyRepository(SentinelDbContext context)
    {
        _context = context;
    }

    public async Task<Policy?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
    {
        return await _context.Policies
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == id, cancellationToken);
    }

    public async Task<IReadOnlyList<Policy>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Policies
            .AsNoTracking()
            .OrderByDescending(p => p.Priority)
            .ThenBy(p => p.CreatedAt)
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Policy>> GetEnabledAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Policies
            .AsNoTracking()
            .Where(p => p.IsEnabled)
            .OrderByDescending(p => p.Priority)
            .ThenBy(p => p.CreatedAt)
            .ToListAsync(cancellationToken);
    }

    public void Add(Policy policy)
    {
        _context.Policies.Add(policy);
    }

    public void Update(Policy policy)
    {
        _context.Policies.Update(policy);
    }

    public void Remove(Policy policy)
    {
        _context.Policies.Remove(policy);
    }

    public async Task<int> RemoveAllAsync(CancellationToken cancellationToken = default)
    {
        // A set-based delete avoids loading every row just to remove it.
        return await _context.Policies.ExecuteDeleteAsync(cancellationToken);
    }
}

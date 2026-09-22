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

    // The single policy owned by a user; null when none exists yet.
    public async Task<Policy?> GetByUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        return await _context.Policies
            .FirstOrDefaultAsync(p => p.UserId == userId, cancellationToken);
    }

    public async Task<IReadOnlyList<Policy>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Policies
            .AsNoTracking()
            .OrderBy(p => p.CreatedAt)
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
}

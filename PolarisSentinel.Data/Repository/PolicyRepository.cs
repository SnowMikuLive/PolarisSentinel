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

    public async Task<Policy?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await _context.Policies
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == id, cancellationToken);
    }

    public async Task<IReadOnlyList<Policy>> GetByUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        return await _context.Policies
            .AsNoTracking()
            .Where(p => p.UserId == userId)
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Policy>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Policies
            .AsNoTracking()
            .OrderBy(p => p.Name)
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

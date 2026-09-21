using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.DataAccess.Data;

namespace PolarisSentinel.DataAccess.Repository;

public class RuleRepository : IRuleRepository
{
    private readonly SentinelDbContext _context;

    public RuleRepository(SentinelDbContext context)
    {
        _context = context;
    }

    public void Add(Rule rule)
    {
        _context.Rules.Add(rule);
    }

    public async Task<IReadOnlyList<Rule>> GetActiveAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Rules
            .AsNoTracking()
            .Where(r => r.ExpiresAt == null || r.ExpiresAt > DateTime.UtcNow)
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Rule>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Rules
            .AsNoTracking()
            //Load the Policy and Alert navigation; otherwise, policyName will always be null.
            .Include(r => r.Policy)
            .Include(r => r.Alert)
            .OrderByDescending(r => r.CreatedAt)
            .ToListAsync(cancellationToken);
    }

    public async Task<Rule?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
    {
        return await _context.Rules
            .FirstOrDefaultAsync(r => r.Id == id, cancellationToken);
    }

    public void Update(Rule rule)
    {
        _context.Rules.Update(rule);
    }

    public void Remove(Rule rule)
    {
        _context.Rules.Remove(rule);
    }
}

using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Data;

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
}

using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Core.Constants;
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

    public async Task<string> NextIdAsync(CancellationToken cancellationToken = default)
    {
        int max = await _context.Database.SqlQuery<int>(
            $"SELECT ISNULL(MAX(TRY_CAST(SUBSTRING([Id], {EntityIds.RulePrefix.Length + 1}, 20) AS INT)), 0) AS [Value] FROM [Rules]")
            .SingleAsync(cancellationToken);
        return EntityIds.Rule(max + 1);
    }

    public async Task<IReadOnlyList<Rule>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Rules
            .AsNoTracking()
            .OrderByDescending(r => r.CreatedAt)
            .ToListAsync(cancellationToken);
    }

    public async Task<Rule?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
    {
        return await _context.Rules
            .FirstOrDefaultAsync(r => r.Id == id, cancellationToken);
    }

    public async Task<Rule?> GetByNameAsync(string name, CancellationToken cancellationToken = default)
    {
        return await _context.Rules
            .AsNoTracking()
            .FirstOrDefaultAsync(r => r.Name == name, cancellationToken);
    }

    public void Update(Rule rule)
    {
        var tracked = _context.Rules
            .FirstOrDefault(r => r.Id == rule.Id);

        if (tracked is null)
        {
            _context.Rules.Attach(rule);
            _context.Entry(rule).State = EntityState.Modified;
            return;
        }

        tracked.Name = rule.Name;
        tracked.PolicyId = rule.PolicyId;
        tracked.AlertId = rule.AlertId;
        tracked.Action = rule.Action;
        tracked.SourceIp = rule.SourceIp;
        tracked.SourcePort = rule.SourcePort;
        tracked.DestinationIp = rule.DestinationIp;
        tracked.DestinationPort = rule.DestinationPort;
        tracked.Protocol = rule.Protocol;
        tracked.Status = rule.Status;
        tracked.CreatedAt = rule.CreatedAt;
        tracked.UpdatedAt = rule.UpdatedAt;
        tracked.ExpiresAt = rule.ExpiresAt;
    }

    public void Remove(Rule rule)
    {
        var existing = _context.Rules.Find(rule.Id);
        if (existing != null)
        {
            _context.Rules.Remove(existing);
        }
    }

    public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return _context.SaveChangesAsync(cancellationToken);
    }
}

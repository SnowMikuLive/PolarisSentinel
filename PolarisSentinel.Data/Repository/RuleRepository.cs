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

    // Single aggregate instead of a full-table read (see AlertRepository.NextIdAsync).
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

    public void Update(Rule rule)
    {
        // Rules are read with AsNoTracking(), so the passed-in instance is detached.
        // Load the tracked row and copy only the scalar columns across so EF never
        // tries to re-attach (and re-insert) a principal row.
        var tracked = _context.Rules
            .FirstOrDefault(r => r.Id == rule.Id);

        if (tracked is null)
        {
            // No existing row (e.g. an entity created in-memory): attach just this rule.
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
        // Remove the tracked row to avoid attaching the same rule twice.
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

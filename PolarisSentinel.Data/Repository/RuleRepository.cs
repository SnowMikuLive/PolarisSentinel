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

    // Sequential ids are derived from the highest existing number, so deleted
    // rows can cause a number to be reused; acceptable for this prototype.
    public async Task<string> NextIdAsync(CancellationToken cancellationToken = default)
    {
        var ids = await _context.Rules.Select(r => r.Id).ToListAsync(cancellationToken);
        return EntityIds.Rule(EntityIds.MaxNumber(ids, EntityIds.RulePrefix) + 1);
    }

    public async Task<IReadOnlyList<Rule>> GetActiveAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTime.Now;
        return await _context.Rules
            .AsNoTracking()
            .Where(r => r.ExpiresAt == null || r.ExpiresAt > now)
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
        // Rules are usually read with AsNoTracking() (and Include(Policy/Alert)), so the
        // passed-in instance is detached and its navigation properties hold detached
        // Policy/Alert instances. Attaching that graph would re-attach those principals
        // and, because Policy/Alert are seed data, EF would try to INSERT them again
        // (duplicate PK 'P-1'/'A-1'). Instead, load the tracked row and copy only the
        // scalar columns across, never touching the navigation graph.
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
        _context.Rules.Remove(rule);
    }

    public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return _context.SaveChangesAsync(cancellationToken);
    }
}

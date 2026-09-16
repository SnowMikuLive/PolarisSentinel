using PolarisSentinel.Core.Interfaces;

namespace PolarisSentinel.Data;

// Single transaction boundary over SentinelDbContext. All repositories share
// the same context instance, so SaveChangesAsync commits every staged change
// atomically.
public class UnitOfWork : IUnitOfWork
{
    private readonly SentinelDbContext _context;

    public UnitOfWork(SentinelDbContext context)
    {
        _context = context;
        Alerts = new AlertRepository(context);
        Rules = new RuleRepository(context);
        Policies = new PolicyRepository(context);
    }

    public IAlertRepository Alerts { get; }

    public IRuleRepository Rules { get; }

    public IPolicyRepository Policies { get; }

    public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return _context.SaveChangesAsync(cancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        return _context.DisposeAsync();
    }
}

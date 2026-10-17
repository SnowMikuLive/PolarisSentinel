using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.DataAccess.Data;

namespace PolarisSentinel.DataAccess.Repository;

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

    public async ValueTask DisposeAsync()
    {
        await _context.DisposeAsync();
        GC.SuppressFinalize(this);
    }
}

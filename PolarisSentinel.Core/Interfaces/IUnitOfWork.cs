namespace PolarisSentinel.Core.Interfaces;

// Transaction boundary over all repositories sharing one DbContext.
// Repositories stage changes; commit happens once via SaveChangesAsync.
public interface IUnitOfWork : IAsyncDisposable
{
    IAlertRepository Alerts { get; }

    IRuleRepository Rules { get; }

    IPolicyRepository Policies { get; }

    IUserRepository Users { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}

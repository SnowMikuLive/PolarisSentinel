namespace PolarisSentinel.Core.Interfaces;

public interface IUnitOfWork : IAsyncDisposable
{
    IAlertRepository Alerts { get; }

    IRuleRepository Rules { get; }

    IPolicyRepository Policies { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}

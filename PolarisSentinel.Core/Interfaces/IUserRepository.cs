using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IUserRepository
{
    Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);
}

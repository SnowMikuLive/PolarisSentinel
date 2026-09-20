using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IUserSettingsRepository
{
    Task<UserSettings?> GetByUserAsync(string userId, CancellationToken cancellationToken = default);

    void Add(UserSettings settings);

    void Update(UserSettings settings);
}

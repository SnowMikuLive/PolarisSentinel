using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IUserSettingsStore
{
    UserSettings Read();

    void Update(Action<UserSettings> mutate);
}

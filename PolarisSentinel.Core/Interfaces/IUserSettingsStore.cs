using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Persists the operator's choices (dry-run, model combination, capture device) so they
// survive a restart and stay fixed until the user changes them again.
public interface IUserSettingsStore
{
    UserSettings Read();

    void Update(Action<UserSettings> mutate);
}

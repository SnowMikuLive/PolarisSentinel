using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// Persists the operator's choices (dry-run, model combination, capture device) so they
// survive a restart and stay fixed until the user changes them again.
public interface IUserSettingsStore
{
    // The current settings; all-null when nothing has been saved yet.
    UserSettings Read();

    // Applies a change and persists it. Read-modify-write is serialized internally, so a
    // single field can be changed without clobbering the others.
    void Update(Action<UserSettings> mutate);
}

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.DataAccess.Data;

namespace PolarisSentinel.DataAccess.Repository;

// Persists the operator's choices in the database (a single row), so they follow the
// database rather than the Windows account. A failure degrades to defaults instead of
// failing startup, matching the previous file-based behaviour.
public sealed class DbUserSettingsStore : IUserSettingsStore
{
    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<DbUserSettingsStore> _logger;
    private readonly object _lock = new();

    public DbUserSettingsStore(IServiceScopeFactory scopes, ILogger<DbUserSettingsStore> logger)
    {
        _scopes = scopes;
        _logger = logger;
    }

    public UserSettings Read()
    {
        lock (_lock)
        {
            try
            {
                using var scope = _scopes.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
                return db.UserSettings.AsNoTracking().OrderBy(s => s.Id).FirstOrDefault() ?? new UserSettings();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not read user settings from the database; using defaults.");
                return new UserSettings();
            }
        }
    }

    public void Update(Action<UserSettings> mutate)
    {
        lock (_lock)
        {
            try
            {
                using var scope = _scopes.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
                var settings = db.UserSettings.OrderBy(s => s.Id).FirstOrDefault();
                if (settings is null)
                {
                    settings = new UserSettings();
                    db.UserSettings.Add(settings);
                }

                mutate(settings);
                db.SaveChanges();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Could not persist user settings to the database.");
            }
        }
    }
}

using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.DataAccess.Data;

namespace PolarisSentinel.DataAccess.Repository;

public class UserSettingsRepository : IUserSettingsRepository
{
    private readonly SentinelDbContext _context;

    public UserSettingsRepository(SentinelDbContext context)
    {
        _context = context;
    }

    public async Task<UserSettings?> GetByUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        return await _context.UserSettings
            .AsNoTracking()
            .FirstOrDefaultAsync(s => s.UserId == userId, cancellationToken);
    }

    public void Add(UserSettings settings)
    {
        _context.UserSettings.Add(settings);
    }

    public void Update(UserSettings settings)
    {
        _context.UserSettings.Update(settings);
    }
}

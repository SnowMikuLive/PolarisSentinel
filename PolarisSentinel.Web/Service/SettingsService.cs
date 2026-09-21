using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Service;

// Per-user settings (detection thresholds + firewall options).
// Defaults come from appsettings.json; overrides are persisted per user in the DB.
public class SettingsService
{
    private readonly IConfiguration _config;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public SettingsService(
        IConfiguration config,
        IServiceScopeFactory scopeFactory,
        IHttpContextAccessor httpContextAccessor)
    {
        _config = config;
        _scopeFactory = scopeFactory;
        _httpContextAccessor = httpContextAccessor;
    }

    // Signed-in user id for the current request; empty when unauthenticated.
    public string CurrentUserId =>
        _httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;

    // Load the current user's settings for synchronous view use.
    public async Task<UserSettings> LoadForCurrentUserAsync(CancellationToken cancellationToken = default)
    {
        return await GetForCurrentUserAsync(cancellationToken);
    }

    // Current user's settings (seeded from appsettings when no row exists yet).
    public async Task<UserSettings> GetForCurrentUserAsync(CancellationToken cancellationToken = default)
    {
        string userId = CurrentUserId;
        if (string.IsNullOrEmpty(userId))
        {
            return Defaults();
        }

        await using var scope = _scopeFactory.CreateAsyncScope();
        var uow = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var settings = await uow.UserSettings.GetByUserAsync(userId, cancellationToken);
        if (settings != null)
        {
            return settings;
        }

        // 首次使用：以 appsettings 默认值建行并保存
        // First use: create a row from the appsettings defaults and persist it
        var seeded = Defaults();
        seeded.UserId = userId;
        uow.UserSettings.Add(seeded);
        await uow.SaveChangesAsync(cancellationToken);
        return seeded;
    }

    // Persist the current user's settings; the owner is always the signed-in user.
    public async Task<UserSettings> SaveForCurrentUserAsync(UserSettings settings, CancellationToken cancellationToken = default)
    {
        string userId = CurrentUserId;
        if (string.IsNullOrEmpty(userId))
        {
            return settings;
        }

        // Ignore any owner supplied by the caller/form.
        settings.UserId = userId;
        settings.UpdatedAt = DateTime.UtcNow;

        await using var scope = _scopeFactory.CreateAsyncScope();
        var uow = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var existing = await uow.UserSettings.GetByUserAsync(userId, cancellationToken);
        if (existing == null)
        {
            uow.UserSettings.Add(settings);
        }
        else
        {
            uow.UserSettings.Update(settings);
        }
        await uow.SaveChangesAsync(cancellationToken);
        return settings;
    }

    // Format a timestamp using the local system time zone.
    public static string Format(DateTime value) =>
        ToLocal(value).ToString("yyyy-MM-dd HH:mm:ss");

    // Convert a stored UTC timestamp to the local system time zone.
    public static DateTime ToLocal(DateTime value)
    {
        var utc = value.Kind == DateTimeKind.Unspecified
            ? DateTime.SpecifyKind(value, DateTimeKind.Utc)
            : value;
        return utc.ToLocalTime();
    }

    // Defaults sourced from appsettings.json (used before a user has saved anything).
    private UserSettings Defaults()
    {
        var policy = _config.GetSection("PolicySettings");

        return new UserSettings
        {
            RfConfidenceThreshold = policy.GetValue<float?>("RfConfidenceThreshold") ?? 0.6f,
            AutoBlockConfidenceThreshold = policy.GetValue<float?>("AutoBlockConfidenceThreshold") ?? 0.8f,
            IfAnomalyThreshold = policy.GetValue<double?>("IfAnomalyThreshold") ?? -0.150806,
            BlockDurationMinutes = policy.GetValue<int?>("BlockDurationMinutes") ?? 60,
            DecisionCooldownSeconds = policy.GetValue<int?>("DecisionCooldownSeconds") ?? 60,
            PreFilterMinPackets = policy.GetValue<int?>("PreFilterMinPackets") ?? 3,
            FlowIdleTimeoutMilliseconds = policy.GetValue<int?>("FlowIdleTimeoutMilliseconds") ?? 120000,
            Allowlist = string.Join(", ", policy.GetSection("Allowlist").Get<string[]>() ?? [])
        };
    }
}

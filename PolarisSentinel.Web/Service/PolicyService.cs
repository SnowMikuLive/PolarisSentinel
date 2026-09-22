using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Service;

// Resolves the signed-in user's policy, seeding a default row on first use.
public class PolicyService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public PolicyService(IServiceScopeFactory scopeFactory, IHttpContextAccessor httpContextAccessor)
    {
        _scopeFactory = scopeFactory;
        _httpContextAccessor = httpContextAccessor;
    }

    // Signed-in user id for the current request; empty when unauthenticated.
    public string CurrentUserId =>
        _httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;

    // The current user's policy, created from defaults when no row exists yet.
    public async Task<Policy> GetForCurrentUserAsync(CancellationToken cancellationToken = default)
    {
        string userId = CurrentUserId;
        if (string.IsNullOrEmpty(userId))
        {
            return Defaults();
        }

        await using var scope = _scopeFactory.CreateAsyncScope();
        var uow = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var policy = await uow.Policies.GetByUserAsync(userId, cancellationToken);
        if (policy != null)
        {
            return policy;
        }

        // First use: create a row from the defaults and persist it.
        var seeded = Defaults();
        seeded.UserId = userId;
        uow.Policies.Add(seeded);
        await uow.SaveChangesAsync(cancellationToken);
        return seeded;
    }

    // Persist the current user's policy; the owner is always the signed-in user.
    public async Task<Policy> SaveForCurrentUserAsync(Policy policy, CancellationToken cancellationToken = default)
    {
        string userId = CurrentUserId;
        if (string.IsNullOrEmpty(userId))
        {
            return policy;
        }

        // Ignore any owner supplied by the caller/form.
        policy.UserId = userId;
        policy.UpdatedAt = DateTime.Now;

        await using var scope = _scopeFactory.CreateAsyncScope();
        var uow = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var existing = await uow.Policies.GetByUserAsync(userId, cancellationToken);
        if (existing == null)
        {
            uow.Policies.Add(policy);
        }
        else
        {
            uow.Policies.Update(policy);
        }
        await uow.SaveChangesAsync(cancellationToken);
        return policy;
    }

    // Default thresholds for a user who has not configured anything yet.
    private static Policy Defaults() => new()
    {
        DetectionSource = DetectionSource.RandomForest,
        RfConfidenceThreshold = 0.6f,
        IfConfidenceThreshold = 0.6f,
        BlockDurationMinutes = 60,
        CreatedAt = DateTime.Now,
        UpdatedAt = DateTime.Now
    };
}

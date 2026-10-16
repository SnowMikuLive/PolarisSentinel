using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.DataAccess.Data;

// Applies EF migrations and optionally seeds the admin; the host aborts startup on failure.
public sealed class SentinelDbInitializer
{
    private readonly SentinelDbContext _db;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly AdminSeedOptions _options;
    private readonly ILogger<SentinelDbInitializer> _logger;

    public SentinelDbInitializer(
        SentinelDbContext db,
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IOptions<AdminSeedOptions> options,
        ILogger<SentinelDbInitializer> logger)
    {
        _db = db;
        _userManager = userManager;
        _roleManager = roleManager;
        _options = options.Value;
        _logger = logger;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await _db.Database.MigrateAsync(cancellationToken);
        _logger.LogInformation("Database migrations applied.");

        await EnsureAdditionalPolicyAsync(cancellationToken);
        await RelaxSeededAiThresholdsAsync(cancellationToken);

        if (!_options.Enabled)
        {
            _logger.LogInformation("Admin seeding disabled; skipping account provisioning.");
            return;
        }

        if (string.IsNullOrWhiteSpace(_options.Password))
        {
            _logger.LogWarning(
                "AdminSeed:Password is not configured. Skipping admin creation. " +
                "Set it via user-secrets or the AdminSeed__Password environment variable.");
            return;
        }

        var role = _options.Role?.Trim();
        if (!string.IsNullOrEmpty(role) && !await _roleManager.RoleExistsAsync(role))
        {
            await _roleManager.CreateAsync(new IdentityRole(role));
        }

        var admin = await _userManager.FindByNameAsync(_options.UserName);
        if (admin is null)
        {
            admin = new ApplicationUser
            {
                UserName = _options.UserName,
                Email = _options.Email,
                EmailConfirmed = true,
                MustChangePassword = true
            };

            var created = await _userManager.CreateAsync(admin, _options.Password);
            if (!created.Succeeded)
            {
                _logger.LogCritical(
                    "Failed to create the initial admin user: {Errors}. Fix the configured " +
                    "AdminSeed:Password (it must satisfy the Identity password policy) and restart, " +
                    "otherwise no account can sign in.",
                    string.Join("; ", created.Errors.Select(e => e.Description)));
                return;
            }

            _logger.LogInformation("Initial admin user '{UserName}' created.", _options.UserName);
        }

        if (!string.IsNullOrEmpty(role) && !await _userManager.IsInRoleAsync(admin, role))
        {
            await _userManager.AddToRoleAsync(admin, role);
        }
    }

    // Adds the Isolation Forest suspicious-traffic policy on databases created before it
    // existed, so it is present without a new migration.
    private async Task EnsureAdditionalPolicyAsync(CancellationToken cancellationToken)
    {
        const string id = "P-8";
        if (await _db.Policies.AnyAsync(p => p.Id == id, cancellationToken))
        {
            return;
        }

        _db.Policies.Add(new Policy
        {
            Id = id,
            UserId = "admin",
            Name = "Isolation Forest suspicious",
            Description = "Surface Isolation Forest-detected suspicious traffic as a monitor alert, regardless of score.",
            DetectionSource = DetectionSource.IsolationForest,
            AttackType = AttackTypes.UnknownAnomaly,
            Action = PolicyAction.Monitor,
            BlockDurationMinutes = 0,
            Priority = 95,
            IsEnabled = true,
            CreatedAt = DateTime.Now,
            UpdatedAt = DateTime.Now
        });

        await _db.SaveChangesAsync(cancellationToken);
        _logger.LogInformation("Added default policy {Id}.", id);
    }

    // Lowered AI alert threshold applied to the seeded detector policies. Only the built-in
    // policy ids are touched (never operator-created ones), and thresholds are only lowered,
    // so an existing database gets the more sensitive models without a new migration.
    private const float RelaxedAiThreshold = 0.5f;

    private static readonly string[] SeededAiPolicyIds = { "P-2", "P-3", "P-6", "P-7" };

    private async Task RelaxSeededAiThresholdsAsync(CancellationToken cancellationToken)
    {
        var policies = await _db.Policies
            .Where(p => SeededAiPolicyIds.Contains(p.Id))
            .ToListAsync(cancellationToken);

        bool changed = false;
        foreach (var policy in policies)
        {
            if (policy.DetectionSource == DetectionSource.RandomForest && policy.RfThreshold is > RelaxedAiThreshold)
            {
                policy.RfThreshold = RelaxedAiThreshold;
                policy.UpdatedAt = DateTime.Now;
                changed = true;
            }
            else if (policy.DetectionSource == DetectionSource.IsolationForest && policy.IfThreshold is > RelaxedAiThreshold)
            {
                policy.IfThreshold = RelaxedAiThreshold;
                policy.UpdatedAt = DateTime.Now;
                changed = true;
            }
        }

        if (changed)
        {
            await _db.SaveChangesAsync(cancellationToken);
            _logger.LogInformation("Lowered seeded AI detection thresholds to {Threshold}.", RelaxedAiThreshold);
        }
    }
}

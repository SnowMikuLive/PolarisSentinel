using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.DataAccess.Data;

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

}

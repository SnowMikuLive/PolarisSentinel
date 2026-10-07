using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

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
        // Apply pending migrations first; without this the schema and seed data stay
        // stale and enum values such as the renamed DetectionSource fail to map.
        await _db.Database.MigrateAsync(cancellationToken);
        _logger.LogInformation("Database migrations applied.");

        if (!_options.Enabled)
        {
            _logger.LogInformation("Admin seeding disabled; skipping account provisioning.");
            return;
        }

        if (string.IsNullOrWhiteSpace(_options.Password))
        {
            // Fail loudly: silently creating a known default password would be
            // a security hole. Set AdminSeed:Password (or AdminSeed__Password).
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
                // The seeded password is a known default, so force a change on first login.
                MustChangePassword = true
            };

            var created = await _userManager.CreateAsync(admin, _options.Password);
            if (!created.Succeeded)
            {
                _logger.LogError(
                    "Failed to create the initial admin user: {Errors}",
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

}

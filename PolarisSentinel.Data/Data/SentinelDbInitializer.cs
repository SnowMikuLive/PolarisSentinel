using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace PolarisSentinel.DataAccess.Data;

//应用EF迁移并可选创建初始管理员；失败时由宿主中止启动。
//Apply EF migrations and optionally seed admin;host aborts startup on failure.
//
//Why this lives here instead of Program.cs:
//-The Web project only needs to call one method;schema and identity
//  bootstrap logic stays next to the DbContext that owns it.
//-The password is supplied through AdminSeedOptions (config/env var/
//  user-secrets),so no credential is hardcoded in source.
public sealed class SentinelDbInitializer
{
    private readonly SentinelDbContext _db;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly AdminSeedOptions _options;
    private readonly ILogger<SentinelDbInitializer> _logger;

    public SentinelDbInitializer(
        SentinelDbContext db,
        UserManager<IdentityUser> userManager,
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
        await MigrateDatabaseAsync(_db, cancellationToken);

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
            admin = new IdentityUser
            {
                UserName = _options.UserName,
                Email = _options.Email,
                EmailConfirmed = true
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

    //先校验__EFMigrationsHistory；未知迁移ID则抛错，不自动删库。
    //Validate __EFMigrationsHistory first;unknown ids throw without dropping data.
    public static async Task MigrateDatabaseAsync(SentinelDbContext db, CancellationToken cancellationToken = default)
    {
        var known = db.Database.GetMigrations().ToHashSet();
        var applied = await db.Database.GetAppliedMigrationsAsync(cancellationToken);
        var unknown = applied.Where(id => !known.Contains(id)).ToArray();
        if (unknown.Length > 0)
        {
            throw new InvalidOperationException(
                "Database uses a different migration history: " + string.Join(", ", unknown) +
                ". Keep a backup and use a separate database for this version, or migrate the old data explicitly.");
        }

        await db.Database.MigrateAsync(cancellationToken);
    }
}

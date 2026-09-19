namespace PolarisSentinel.DataAccess.Data;

// Configuration for the initial administrator account.
// Bound from the "AdminSeed" configuration section.
//
// SECURITY: never commit a real password here. Supply it at runtime via
// user-secrets (dev) or an environment variable (prod):
//   AdminSeed__Password=...
public sealed class AdminSeedOptions
{
    public const string SectionName = "AdminSeed";

    // Set to false to skip seeding entirely (e.g. when the account is
    // provisioned out-of-band). Seeding never overwrites an existing user.
    public bool Enabled { get; set; } = true;

    public string UserName { get; set; } = "admin";

    public string Email { get; set; } = "admin@polaris.local";

    // Role granted to the seeded account. Empty means no role.
    public string Role { get; set; } = "Administrator";

    // No default on purpose: an unset password must fail loudly rather than
    // silently fall back to a well-known credential.
    public string? Password { get; set; } = "Admin123!"; // default for dev only; override in production
}

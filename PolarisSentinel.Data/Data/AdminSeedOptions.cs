namespace PolarisSentinel.DataAccess.Data;

public sealed class AdminSeedOptions
{
    public const string SectionName = "AdminSeed";

    public bool Enabled { get; set; } = true;

    public string UserName { get; set; } = "admin";

    public string Email { get; set; } = "admin@polaris.local";


    public string Role { get; set; } = "Administrator";

    public string? Password { get; set; }
}

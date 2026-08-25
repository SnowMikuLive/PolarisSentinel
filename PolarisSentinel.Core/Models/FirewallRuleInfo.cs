namespace PolarisSentinel.Core.Models;

public class FirewallRuleInfo
{
    public required string Name { get; init; }
    public required string RemoteAddress { get; init; }
    public required bool Enabled { get; init; }
    public required bool IsBlockRule { get; init; }

    public required bool IsManagedByPolarisSentinel { get; init; }
}

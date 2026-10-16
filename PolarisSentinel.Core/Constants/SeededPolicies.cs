namespace PolarisSentinel.Core.Constants;

public static class SeededPolicies
{
    public static readonly string[] Ids = { "P-1", "P-2", "P-3", "P-4", "P-5", "P-6", "P-7", "P-8" };

    public static bool IsSeeded(string? id) =>
        !string.IsNullOrEmpty(id) && Ids.Contains(id, StringComparer.OrdinalIgnoreCase);
}

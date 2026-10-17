namespace PolarisSentinel.Core.Constants;

using PolarisSentinel.Core.Enums;

public static class AttackTypes
{
    public const string Benign = nameof(AttackType.Benign);
    public const string DoS = nameof(AttackType.DoS);
    public const string PortScan = nameof(AttackType.PortScan);
    public const string BruteForce = nameof(AttackType.BruteForce);

    public const string UnknownAnomaly = nameof(AttackType.Unknown_Anomaly);

    public static IReadOnlyList<string> All { get; } =
        Array.AsReadOnly(Enum.GetNames<AttackType>());

    public static IReadOnlyList<string> Selectable { get; } =
        Array.AsReadOnly(Enum.GetNames<AttackType>().Where(n => n != Benign).ToArray());

    public static bool IsDefined(string? attackType) =>
        !string.IsNullOrEmpty(attackType) && Enum.IsDefined(typeof(AttackType), attackType);

    public static IReadOnlyList<string> Malicious { get; } =
        Array.AsReadOnly(new[] { DoS, PortScan, BruteForce });

    public static bool IsMalicious(string? attackType) =>
        !string.IsNullOrEmpty(attackType) && Malicious.Contains(attackType, StringComparer.Ordinal);

    public static bool TryParse(string? attackType, out string result)
    {
        result = string.Empty;
        if (string.IsNullOrWhiteSpace(attackType))
        {
            return false;
        }

        string? match = All.FirstOrDefault(name =>
            string.Equals(name, attackType, StringComparison.OrdinalIgnoreCase));

        if (match is not null)
        {
            result = match;
            return true;
        }

        return false;
    }
}

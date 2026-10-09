namespace PolarisSentinel.Core.Constants;

using PolarisSentinel.Core.Enums;

// The four attack categories. Sub-type detail lives in the alert's Reason string.
// Every value here MUST be a member of the AttackType enum: the enum is the
// single source of truth for what the system can report.
public static class AttackTypes
{
    public const string Benign = nameof(AttackType.Benign);
    public const string DoS = nameof(AttackType.DoS);
    public const string PortScan = nameof(AttackType.PortScan);
    public const string BruteForce = nameof(AttackType.BruteForce);

    public const string UnknownAnomaly = nameof(AttackType.Unknown_Anomaly);

    public static readonly string[] All = Enum.GetNames<AttackType>();

    public static readonly string[] Selectable =
        Enum.GetNames<AttackType>().Where(n => n != Benign).ToArray();

    public static bool IsDefined(string? attackType) =>
        !string.IsNullOrEmpty(attackType) && Enum.IsDefined(typeof(AttackType), attackType);

    public static readonly string[] Malicious =
    {
        DoS,
        PortScan,
        BruteForce
    };

    public static bool IsMalicious(string? attackType) =>
        !string.IsNullOrEmpty(attackType) && Array.IndexOf(Malicious, attackType) >= 0;

    public static bool TryParse(string? attackType, out string result)
    {
        result = string.Empty;
        if (string.IsNullOrWhiteSpace(attackType))
        {
            return false;
        }

        foreach (string name in All)
        {
            if (string.Equals(name, attackType, StringComparison.OrdinalIgnoreCase))
            {
                result = name;
                return true;
            }
        }

        return false;
    }
}

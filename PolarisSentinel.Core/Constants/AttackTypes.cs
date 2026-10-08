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

    // Isolation Forest anomaly with no known category.
    public const string UnknownAnomaly = nameof(AttackType.Unknown_Anomaly);

    // Every attack category the system can produce, for UI dropdowns.
    public static readonly string[] All = Enum.GetNames<AttackType>();

    // Categories a policy can match on (Benign is never an attack).
    public static readonly string[] Selectable =
        Enum.GetNames<AttackType>().Where(n => n != Benign).ToArray();

    // True when the value is one of the AttackType enum members.
    public static bool IsDefined(string? attackType) =>
        !string.IsNullOrEmpty(attackType) && Enum.IsDefined(typeof(AttackType), attackType);

    // The named attack categories the AI engine reports as confirmed malicious traffic.
    // Unknown_Anomaly is deliberately excluded: an unnamed anomaly is suspicious, not a
    // confirmed attack, so it must never be labelled malicious on its own.
    public static readonly string[] Malicious =
    {
        DoS,
        PortScan,
        BruteForce
    };

    // True when the attack type is a confirmed malicious category (not benign, not an
    // unnamed anomaly).
    public static bool IsMalicious(string? attackType) =>
        !string.IsNullOrEmpty(attackType) && Array.IndexOf(Malicious, attackType) >= 0;

    // Normalises an external label (e.g. an ONNX class name) onto an enum member.
    // Returns false when the label is not one of the five categories.
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

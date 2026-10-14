namespace PolarisSentinel.Core.Enums;

// The four attack categories the system reports. Sub-types (SYN flood, UDP scan, ...)
// are carried in the alert's Reason field instead of being separate categories.
public enum AttackType
{
    Benign,

    DoS,

    PortScan,

    BruteForce,

    Unknown_Anomaly
}

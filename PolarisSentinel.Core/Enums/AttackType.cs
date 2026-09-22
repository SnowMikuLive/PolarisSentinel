namespace PolarisSentinel.Core.Enums;

// The four attack categories the system reports. Sub-types (SYN flood, UDP scan, ...)
// are carried in the alert's Reason field instead of being separate categories.
public enum AttackType
{
    //No attack detected.
    Benign,

    // Denial of service: SYN / UDP / ACK / ICMP floods.
    DoS,

    // Port scanning: SYN / connect / FIN-NULL-Xmas / UDP scans, ICMP sweeps.
    PortScan,

    // Credential brute force against SSH / FTP.
    BruteForce,

    // Isolation Forest anomaly with no known category.
    Unknown_Anomaly
}

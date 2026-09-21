namespace PolarisSentinel.Core.Constants;

public static class AttackTypes
{
    public const string Benign = "Benign";
    public const string DoS = "DoS";
    public const string PortScan = "PortScan";
    public const string BruteForce = "BruteForce";

    //For Isolation Forest
    public const string UnknownAnomaly = "Unknown_Anomaly";

    //For the rule-based pre-filter
    public const string SynFlood = "SynFlood";
    public const string SuspiciousTcpFlags = "SuspiciousTcpFlags";

    // DoS family
    public const string UdpFlood = "UdpFlood";
    public const string AckFlood = "AckFlood";
    public const string IcmpFlood = "IcmpFlood";

    // Port scanning family
    public const string SynScan = "SynScan";
    public const string ConnectScan = "ConnectScan";
    public const string FinNullXmasScan = "FinNullXmasScan";
    public const string UdpScan = "UdpScan";
    public const string IcmpSweep = "IcmpSweep";

    // Brute force family
    public const string SshBruteForce = "SshBruteForce";
    public const string FtpBruteForce = "FtpBruteForce";
}

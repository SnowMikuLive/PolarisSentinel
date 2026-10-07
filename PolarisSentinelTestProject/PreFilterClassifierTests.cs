using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Core.Services;

namespace PolarisSentienlUnitTestProject;

// Core of the single-flow pre-filter: small one-way probe bursts are flagged as a suspected
// scan, while payload-heavy one-way app traffic is left alone.
[TestClass]
public class PreFilterClassifierTests
{
    private static PreFilter Create() => new(DetectionThresholds.Preset(DetectionSensitivity.High));

    private static FlowStatistics Udp(int fwdPackets, double meanPayloadBytes) => new()
    {
        Protocol = ProtocolNumbers.Udp,
        DestinationPort = 1234,
        FwdPackets = fwdPackets,
        BwdPackets = 0,
        PacketSizeMean = meanPayloadBytes,
        DurationSeconds = 0.2
    };

    // A burst of small one-way UDP probes is forwarded to the AI engine as a suspected scan.
    [TestMethod]
    public void UdpProbeBurst_ShouldBeScanned()
    {
        var verdict = Create().Classify(Udp(fwdPackets: 20, meanPayloadBytes: 20));

        Assert.IsTrue(verdict.IsSuspicious);
        Assert.AreEqual("PortScan: UDP port scan", verdict.Description);
    }

    // A short payload-heavy one-way UDP flow is media/bulk traffic, not a probe burst.
    [TestMethod]
    public void BulkOneWayUdp_ShouldNotBeScanned()
    {
        var verdict = Create().Classify(Udp(fwdPackets: 20, meanPayloadBytes: 1200));

        Assert.IsFalse(verdict.IsSuspicious);
    }
}

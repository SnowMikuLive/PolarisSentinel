using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Core.Services;

namespace PolarisSentienlUnitTestProject;

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

    [TestMethod]
    public void UdpProbeBurst_ShouldBeScanned()
    {
        var verdict = Create().Classify(Udp(fwdPackets: 20, meanPayloadBytes: 20));

        Assert.IsTrue(verdict.IsSuspicious);
        Assert.AreEqual("PortScan: UDP port scan", verdict.Description);
    }

    [TestMethod]
    public void BulkOneWayUdp_ShouldNotBeScanned()
    {
        var verdict = Create().Classify(Udp(fwdPackets: 20, meanPayloadBytes: 1200));

        Assert.IsFalse(verdict.IsSuspicious);
    }

    [TestMethod]
    public void OrdinaryWebTraffic_ShouldBeNormal()
    {
        var flow = new FlowStatistics
        {
            Protocol = ProtocolNumbers.Tcp,
            DestinationPort = 443,
            FwdPackets = 30,
            BwdPackets = 28,
            FwdBytes = 4000,
            BwdBytes = 9000,
            SynCount = 1,
            AckCount = 40,
            DurationSeconds = 5.0,
            PacketSizeMean = 250
        };

        var verdict = Create().Classify(flow);

        Assert.IsFalse(verdict.IsSuspicious);
        Assert.IsFalse(verdict.IsKnownAttack);
    }

    [TestMethod]
    public void AuthPortTraffic_ShouldBeRelevant()
    {
        var flow = new FlowStatistics
        {
            Protocol = ProtocolNumbers.Tcp,
            DestinationPort = 22,
            FwdPackets = 8,
            BwdPackets = 6,
            SynCount = 1,
            AckCount = 8,
            DurationSeconds = 3.0,
            PacketSizeMean = 120
        };

        var verdict = Create().Classify(flow);

        Assert.IsTrue(verdict.IsSuspicious);
    }
}

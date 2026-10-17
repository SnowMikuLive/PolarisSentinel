using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Core.Services;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class SourceBehaviorTrackerTests
{
    private static readonly DateTime Start = new(2026, 10, 4, 12, 0, 0);
    private const string Attacker = "203.0.113.66";
    private const string Victim = "192.168.1.10";

    private static SourceBehaviorTracker CreateTracker() =>
        new(TimeSpan.FromSeconds(10), DetectionThresholds.Preset(DetectionSensitivity.High));

    private static PacketObservation Syn(int port, int msOffset, bool inbound = true) =>
        new(Attacker, Victim, port, ProtocolNumbers.Tcp, IsSyn: true, IsRst: false, PacketSize: 60, Start.AddMilliseconds(msOffset), IsInbound: inbound);

    private static PacketObservation Fin(int port, int msOffset) =>
        new(Attacker, Victim, port, ProtocolNumbers.Tcp, IsSyn: false, IsRst: false, PacketSize: 60, Start.AddMilliseconds(msOffset), IsInbound: true, IsFin: true);

    private static PacketObservation UdpProbe(int port, int msOffset) =>
        new(Attacker, Victim, port, ProtocolNumbers.Udp, IsSyn: false, IsRst: false, PacketSize: 40, Start.AddMilliseconds(msOffset), IsInbound: true);

    private static PacketObservation SynAck(int localPort, int msOffset) =>
        new(Victim, Attacker, localPort, ProtocolNumbers.Tcp, IsSyn: true, IsRst: false, PacketSize: 60, Start.AddMilliseconds(msOffset), IsInbound: true, IsFin: false, IsAck: true);

    [TestMethod]
    public void PortScan_ManyDistinctPorts_ShouldBeDetected()
    {
        var tracker = CreateTracker();

        for (int i = 0; i < 20; i++)
        {
            tracker.Observe(Syn(port: 1000 + i, msOffset: i));
        }

        var verdict = tracker.Evaluate(Attacker, Start.AddSeconds(1));

        Assert.IsNotNull(verdict);
        Assert.IsTrue(verdict.IsKnownAttack);
        Assert.AreEqual(AttackTypes.PortScan, verdict.AttackType);
    }

    [TestMethod]
    public void MultiPortDos_OneSourceManyPorts_ShouldBeDetected()
    {
        var tracker = CreateTracker();

        for (int port = 0; port < 25; port++)
        {
            for (int i = 0; i < 10; i++)
            {
                tracker.Observe(Syn(port: 1000 + port, msOffset: port * 10 + i));
            }
        }

        var verdict = tracker.Evaluate(Attacker, Start.AddSeconds(1));

        Assert.IsNotNull(verdict);
        Assert.IsTrue(verdict.IsKnownAttack);
        Assert.AreEqual(AttackTypes.DoS, verdict.AttackType);
    }

    [TestMethod]
    public void EvaluateFast_ShouldFireImmediatelyOnThreshold()
    {
        var tracker = CreateTracker();
        PreFilterResult? verdict = null;

        for (int i = 0; i < 250; i++)
        {
            var packet = Syn(port: 80, msOffset: i);
            tracker.Observe(packet);
            verdict = tracker.EvaluateFast(packet);
            if (verdict is not null)
            {
                break;
            }
        }

        Assert.IsNotNull(verdict);
        Assert.IsTrue(verdict.IsKnownAttack);
        Assert.AreEqual(AttackTypes.DoS, verdict.AttackType);
    }
    [TestMethod]
    public void OutboundPackets_ShouldBeIgnored()
    {
        var tracker = CreateTracker();
        PreFilterResult? verdict = null;

        for (int i = 0; i < 300; i++)
        {
            var packet = Syn(port: 7000 + i, msOffset: i * 5, inbound: false);
            tracker.Observe(packet);
            verdict = tracker.EvaluateFast(packet);
        }

        Assert.IsNull(verdict);
        Assert.IsNull(tracker.Evaluate(Attacker, Start.AddSeconds(2)));
    }

    [TestMethod]
    public void SynFlood_WithStrayFin_ShouldStillBeDetected()
    {
        var thresholds = DetectionThresholds.Preset(DetectionSensitivity.High) with
        {
            SynFloodSourceSyns = 20,
            FloodPackets = 400,
            FloodDistinctPorts = 50,
            PortScanDistinctPorts = 50,
            GlobalFloodPackets = 4000,
            GlobalFloodDistinctSources = 50
        };

        var tracker = new SourceBehaviorTracker(TimeSpan.FromSeconds(10), thresholds);

        tracker.Observe(Fin(port: 80, msOffset: 0));

        for (int i = 0; i < 40; i++)
        {
            tracker.Observe(Syn(port: 80, msOffset: 10 + i));
        }

        var verdict = tracker.Evaluate(Attacker, Start.AddSeconds(2));

        Assert.IsNotNull(verdict);
        Assert.AreEqual(AttackTypes.DoS, verdict.AttackType);
        Assert.Contains("SYN flood", verdict.Description!);
    }
}

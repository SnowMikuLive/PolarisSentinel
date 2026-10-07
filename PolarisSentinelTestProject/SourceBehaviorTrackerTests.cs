using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Core.Services;

namespace PolarisSentienlUnitTestProject;

// Verifies the source-IP behavioural tracker that catches attacks spread across many
// short flows (port scans, brute-force runs, spoofed-source floods).
[TestClass]
public class SourceBehaviorTrackerTests
{
    private static readonly DateTime Start = new(2026, 10, 4, 12, 0, 0);
    private const string Attacker = "203.0.113.66";
    private const string Victim = "192.168.1.10";

    private static SourceBehaviorTracker CreateTracker() => new(TimeSpan.FromSeconds(10));

    private static PacketObservation Syn(int port, int msOffset) =>
        new(Attacker, Victim, port, ProtocolNumbers.Tcp, IsSyn: true, IsRst: false, PacketSize: 60, Start.AddMilliseconds(msOffset));

    private static PacketObservation Icmp(int msOffset) =>
        new(Attacker, Victim, 0, ProtocolNumbers.Icmp, IsSyn: false, IsRst: false, PacketSize: 64, Start.AddMilliseconds(msOffset));

    // A scan touching many distinct ports is caught even though each port is its own flow.
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

    // A few distinct ports (normal browsing) must not be flagged.
    [TestMethod]
    public void FewDistinctPorts_ShouldNotBeDetected()
    {
        var tracker = CreateTracker();

        for (int i = 0; i < 5; i++)
        {
            tracker.Observe(Syn(port: 80 + i, msOffset: i));
        }

        Assert.IsNull(tracker.Evaluate(Attacker, Start.AddSeconds(1)));
    }

    // Repeated new connections to SSH are a brute-force run.
    [TestMethod]
    public void SshBruteForce_ManyConnections_ShouldBeDetected()
    {
        var tracker = CreateTracker();

        for (int i = 0; i < 10; i++)
        {
            tracker.Observe(Syn(port: 22, msOffset: i * 100));
        }

        var verdict = tracker.Evaluate(Attacker, Start.AddSeconds(1));

        Assert.IsNotNull(verdict);
        Assert.AreEqual(AttackTypes.BruteForce, verdict.AttackType);
        StringAssert.Contains(verdict.Description, "SSH");
    }

    // Repeated new connections to FTP are a brute-force run.
    [TestMethod]
    public void FtpBruteForce_ManyConnections_ShouldBeDetected()
    {
        var tracker = CreateTracker();

        for (int i = 0; i < 10; i++)
        {
            tracker.Observe(Syn(port: 21, msOffset: i * 100));
        }

        var verdict = tracker.Evaluate(Attacker, Start.AddSeconds(1));

        Assert.IsNotNull(verdict);
        Assert.AreEqual(AttackTypes.BruteForce, verdict.AttackType);
        StringAssert.Contains(verdict.Description, "FTP");
    }

    // A spoofed-source SYN flood (each SYN a different source port) is still caught.
    [TestMethod]
    public void SynFlood_ManySynsNoAck_ShouldBeDetected()
    {
        var tracker = CreateTracker();

        for (int i = 0; i < 150; i++)
        {
            tracker.Observe(Syn(port: 80, msOffset: i));
        }

        var verdict = tracker.Evaluate(Attacker, Start.AddSeconds(1));

        Assert.IsNotNull(verdict);
        Assert.AreEqual(AttackTypes.DoS, verdict.AttackType);
    }

    // Observations older than the window must age out, so a slow trickle is not a scan.
    [TestMethod]
    public void ObservationsOutsideWindow_ShouldAgeOut()
    {
        var tracker = CreateTracker();

        // 20 distinct ports, but spread 2 seconds apart over 40s, so at most 5 remain
        // inside the 10s window at any evaluation time.
        for (int i = 0; i < 20; i++)
        {
            tracker.Observe(Syn(port: 1000 + i, msOffset: i * 2000));
        }

        Assert.IsNull(tracker.Evaluate(Attacker, Start.AddSeconds(40)));
    }

    // An unknown source has no window and is never flagged.
    [TestMethod]
    public void UnknownSource_ShouldNotBeDetected()
    {
        var tracker = CreateTracker();
        tracker.Observe(Syn(port: 22, msOffset: 0));

        Assert.IsNull(tracker.Evaluate("198.51.100.9", Start.AddSeconds(1)));
    }

    // A sustained ICMP burst from one source is an aggregate ICMP flood.
    [TestMethod]
    public void IcmpFlood_ManyIcmpPackets_ShouldBeDetected()
    {
        var tracker = CreateTracker();

        for (int i = 0; i < 60; i++)
        {
            tracker.Observe(Icmp(msOffset: i));
        }

        var verdict = tracker.Evaluate(Attacker, Start.AddSeconds(1));

        Assert.IsNotNull(verdict);
        Assert.IsTrue(verdict.IsKnownAttack);
        Assert.AreEqual(AttackTypes.DoS, verdict.AttackType);
        StringAssert.Contains(verdict.Description, "ICMP");
    }

    // A normal handful of pings must not be flagged as a flood.
    [TestMethod]
    public void FewIcmpPackets_ShouldNotBeDetected()
    {
        var tracker = CreateTracker();

        for (int i = 0; i < 5; i++)
        {
            tracker.Observe(Icmp(msOffset: i * 1000));
        }

        Assert.IsNull(tracker.Evaluate(Attacker, Start.AddSeconds(6)));
    }

    // A DoS from one IP spread across many destination ports: each port is its own short
    // flow, so the per-flow pre-filter misses it; the aggregate packet count catches it.
    [TestMethod]
    public void MultiPortDos_OneSourceManyPorts_ShouldBeDetected()
    {
        var tracker = CreateTracker();

        // 250 packets spread over 25 distinct ports (10 each) in the window.
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

    // A spoofed random-source flood (hping3 --rand-source): every packet has a different
    // source, so no per-source window accumulates; the global aggregate catches it.
    [TestMethod]
    public void RandomSourceFlood_ManyDistinctSources_ShouldBeDetected()
    {
        var tracker = CreateTracker();

        for (int i = 0; i < 1200; i++)
        {
            // A fresh source IP per packet, as a spoofed flood produces.
            string spoofed = $"10.0.{i / 256}.{i % 256}";
            var packet = new PacketObservation(spoofed, Victim, 80, ProtocolNumbers.Tcp,
                IsSyn: true, IsRst: false, PacketSize: 60, Start.AddMilliseconds(i));
            tracker.Observe(packet);
        }

        var verdict = tracker.EvaluateFast(new PacketObservation(Attacker, Victim, 80, ProtocolNumbers.Tcp,
            IsSyn: true, IsRst: false, PacketSize: 60, Start.AddMilliseconds(1200)));

        Assert.IsNotNull(verdict);
        Assert.IsTrue(verdict.IsKnownAttack);
        Assert.AreEqual(AttackTypes.DoS, verdict.AttackType);
        StringAssert.Contains(verdict.Description, "Global");
    }

    // The fast-path returns a verdict the instant a threshold is crossed, without waiting
    // for idle expiry.
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
}

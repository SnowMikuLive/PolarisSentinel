using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Core.Services;

namespace PolarisSentienlUnitTestProject;

// Key behaviours of the source-IP tracker: port scan, brute force, multi-port/global flood,
// and the per-packet fast-path.
[TestClass]
public class SourceBehaviorTrackerTests
{
    private static readonly DateTime Start = new(2026, 10, 4, 12, 0, 0);
    private const string Attacker = "203.0.113.66";
    private const string Victim = "192.168.1.10";

    private static SourceBehaviorTracker CreateTracker() => new(TimeSpan.FromSeconds(10));

    private static PacketObservation Syn(int port, int msOffset) =>
        new(Attacker, Victim, port, ProtocolNumbers.Tcp, IsSyn: true, IsRst: false, PacketSize: 60, Start.AddMilliseconds(msOffset));

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
        Assert.AreEqual(20, verdict.Aggregate!.DistinctPorts);
    }

    // Repeated new connections to an authentication port are a brute-force run.
    [TestMethod]
    public void BruteForce_ManyConnections_ShouldBeDetected()
    {
        var tracker = CreateTracker();

        for (int i = 0; i < 10; i++)
        {
            tracker.Observe(Syn(port: 22, msOffset: i * 100));
        }

        var verdict = tracker.Evaluate(Attacker, Start.AddSeconds(1));

        Assert.IsNotNull(verdict);
        Assert.AreEqual(AttackTypes.BruteForce, verdict.AttackType);
    }

    // A DoS from one IP spread across many destination ports: each port is its own short
    // flow, so the per-flow pre-filter misses it; the aggregate packet count catches it.
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

    // A spoofed random-source flood (hping3 --rand-source): every packet has a different
    // source, so no per-source window accumulates; the global aggregate catches it.
    [TestMethod]
    public void RandomSourceFlood_ManyDistinctSources_ShouldBeDetected()
    {
        var tracker = CreateTracker();

        for (int i = 0; i < 1200; i++)
        {
            string spoofed = $"10.0.{i / 256}.{i % 256}";
            tracker.Observe(new PacketObservation(spoofed, Victim, 80, ProtocolNumbers.Tcp,
                IsSyn: true, IsRst: false, PacketSize: 60, Start.AddMilliseconds(i)));
        }

        var verdict = tracker.EvaluateFast(Syn(port: 80, msOffset: 1200));

        Assert.IsNotNull(verdict);
        Assert.IsTrue(verdict.IsKnownAttack);
        Assert.AreEqual(AttackTypes.DoS, verdict.AttackType);
    }

    // The fast-path returns a verdict the instant a threshold is crossed, without expiry.
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

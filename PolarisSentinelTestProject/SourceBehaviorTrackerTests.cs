using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Core.Services;

namespace PolarisSentienlUnitTestProject;

// Core of the cross-flow detector: port scan, multi-port DoS, and the per-packet fast-path.
[TestClass]
public class SourceBehaviorTrackerTests
{
    private static readonly DateTime Start = new(2026, 10, 4, 12, 0, 0);
    private const string Attacker = "203.0.113.66";
    private const string Victim = "192.168.1.10";

    private static SourceBehaviorTracker CreateTracker() =>
        new(TimeSpan.FromSeconds(10), DetectionThresholds.Preset(DetectionSensitivity.High));

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

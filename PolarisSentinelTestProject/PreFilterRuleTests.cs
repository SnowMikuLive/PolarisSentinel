using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.TrafficCapture.Internal;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class PreFilterRuleTests
    {
        private const byte Tcp = ProtocolNumbers.Tcp;
        private const byte Udp = ProtocolNumbers.Udp;
        private const byte Icmp = ProtocolNumbers.Icmp;

        #region DoS Family

        [TestMethod]
        public void SynFlood_ShouldBeDetected()
        {
            var flow = CreateFlow(Tcp, 80, durationSeconds: 2);
            flow.FwdPackets = 200;
            flow.BwdPackets = 0;
            flow.SynCount = 200;

            AssertVerdict(flow, AttackTypes.SynFlood);
        }

        [TestMethod]
        public void UdpFlood_ShouldBeDetected()
        {
            var flow = CreateFlow(Udp, 53, durationSeconds: 1);
            flow.FwdPackets = 500;
            flow.BwdPackets = 0;

            AssertVerdict(flow, AttackTypes.UdpFlood);
        }

        [TestMethod]
        public void AckFlood_ShouldBeDetected()
        {
            var flow = CreateFlow(Tcp, 80, durationSeconds: 2);
            flow.FwdPackets = 200;
            flow.BwdPackets = 0;
            flow.AckCount = 200;

            AssertVerdict(flow, AttackTypes.AckFlood);
        }

        [TestMethod]
        public void IcmpFlood_ShouldBeDetected()
        {
            var flow = CreateFlow(Icmp, 0, durationSeconds: 1);
            flow.FwdPackets = 500;
            flow.BwdPackets = 0;

            AssertVerdict(flow, AttackTypes.IcmpFlood);
        }

        #endregion

        #region Port Scan Family

        [TestMethod]
        public void SynScan_ShouldBeDetected()
        {
            var flow = CreateFlow(Tcp, 80, durationSeconds: 1);
            flow.FwdPackets = 20;
            flow.BwdPackets = 0;
            flow.SynCount = 20;
            flow.RstCount = 20;

            AssertVerdict(flow, AttackTypes.SynScan);
        }

        [TestMethod]
        public void ConnectScan_ShouldBeDetected()
        {
            var flow = CreateFlow(Tcp, 80, durationSeconds: 1);
            flow.FwdPackets = 20;
            flow.BwdPackets = 2;
            flow.SynCount = 10;
            flow.AckCount = 15;
            flow.RstCount = 5;

            AssertVerdict(flow, AttackTypes.ConnectScan);
        }

        [TestMethod]
        public void FinNullXmasScan_ShouldBeDetected()
        {
            var flow = CreateFlow(Tcp, 80, durationSeconds: 1);
            flow.FwdPackets = 20;
            flow.BwdPackets = 0;
            flow.FinCount = 20;

            AssertVerdict(flow, AttackTypes.FinNullXmasScan);
        }

        [TestMethod]
        public void UdpScan_ShouldBeDetected()
        {
            var flow = CreateFlow(Udp, 161, durationSeconds: 1);
            flow.FwdPackets = 20;
            flow.BwdPackets = 0;

            AssertVerdict(flow, AttackTypes.UdpScan);
        }

        [TestMethod]
        public void IcmpSweep_ShouldBeDetected()
        {
            var flow = CreateFlow(Icmp, 0, durationSeconds: 1);
            flow.FwdPackets = 10;
            flow.BwdPackets = 0;

            AssertVerdict(flow, AttackTypes.IcmpSweep);
        }

        #endregion

        #region Brute Force Family

        [TestMethod]
        public void SshBruteForce_ShouldBeDetected()
        {
            var flow = CreateFlow(Tcp, 22, durationSeconds: 30);
            flow.FwdPackets = 40;
            flow.BwdPackets = 35;
            flow.SynCount = 8;
            AddFlatSizes(flow, 60, 40);

            AssertVerdict(flow, AttackTypes.SshBruteForce);
        }

        [TestMethod]
        public void FtpBruteForce_ShouldBeDetected()
        {
            var flow = CreateFlow(Tcp, 21, durationSeconds: 30);
            flow.FwdPackets = 40;
            flow.BwdPackets = 35;
            flow.SynCount = 8;
            AddFlatSizes(flow, 60, 40);

            AssertVerdict(flow, AttackTypes.FtpBruteForce);
        }

        #endregion

        #region Benign Traffic

        [TestMethod]
        public void NormalHttpTraffic_ShouldNotBeFlagged()
        {
            var flow = CreateFlow(Tcp, 443, durationSeconds: 5);
            flow.FwdPackets = 20;
            flow.BwdPackets = 30;
            flow.FwdBytes = 4000;
            flow.BwdBytes = 20000;
            flow.SynCount = 1;
            AddFlatSizes(flow, 500, 400);

            var verdict = new PreFilter(3).Classify(flow, out bool suspicious);

            Assert.IsNull(verdict);
            Assert.IsFalse(suspicious);
        }

        [TestMethod]
        public void TooFewPackets_ShouldBeDropped()
        {
            var flow = CreateFlow(Tcp, 443, durationSeconds: 5);
            flow.FwdPackets = 1;
            flow.BwdPackets = 1;

            var verdict = new PreFilter(3).Classify(flow, out bool suspicious);

            Assert.IsNull(verdict);
            Assert.IsFalse(suspicious);
        }

        #endregion

        #region Helper Methods

        private static void AssertVerdict(FlowRecord flow, string expectedAttackType)
        {
            var verdict = new PreFilter(3).Classify(flow, out bool suspicious);

            Assert.IsNotNull(verdict, $"Expected {expectedAttackType} verdict.");
            Assert.AreEqual(expectedAttackType, verdict.AttackType);
            Assert.IsFalse(suspicious);
        }

        private static FlowRecord CreateFlow(byte protocol, int destinationPort, double durationSeconds)
        {
            var start = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return new FlowRecord
            {
                StartTime = start,
                LastSeenTime = start.AddSeconds(durationSeconds),
                Protocol = protocol,
                DestinationPort = destinationPort
            };
        }

        // Feeds near-constant sizes so the flow looks like flat, repeating brute-force traffic.
        private static void AddFlatSizes(FlowRecord flow, int size, int count)
        {
            for (int i = 0; i < count; i++)
            {
                flow.PacketSizeStats.Add(size);
            }
        }

        #endregion
    }
}

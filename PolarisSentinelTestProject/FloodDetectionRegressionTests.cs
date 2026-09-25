using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.TrafficCapture.Internal;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class FloodDetectionRegressionTests
    {
        [TestMethod]
        public void UdpFlood_ShouldBeDetected()
        {
            var filter = new PreFilter(3);
            var flow = new FlowRecord
            {
                StartTime = DateTime.Now.AddSeconds(-5),
                LastSeenTime = DateTime.Now,
                Protocol = ProtocolNumbers.Udp,
                DestinationPort = 80
            };

            for (int i = 0; i < 2000; i++)
            {
                flow.FwdPackets++;
                flow.FwdBytes += 1200;
                flow.PacketSizeStats.Add(1200);
            }

            var verdict = filter.Classify(flow, out bool suspicious);

            Assert.IsNotNull(verdict, "UDP flood was not detected by the pre-filter.");
            Assert.AreEqual(AttackTypes.DoS, verdict.AttackType);
            Assert.AreEqual("prefilter_udp_flood", verdict.Reason);
        }

        [TestMethod]
        public void SynFlood_ShouldBeDetected()
        {
            var filter = new PreFilter(3);
            var flow = new FlowRecord
            {
                StartTime = DateTime.Now.AddSeconds(-5),
                LastSeenTime = DateTime.Now,
                Protocol = ProtocolNumbers.Tcp,
                DestinationPort = 80
            };

            for (int i = 0; i < 200; i++)
            {
                flow.FwdPackets++;
                flow.FwdBytes += 60;
                flow.PacketSizeStats.Add(60);
            }
            flow.SynCount = 200;

            var verdict = filter.Classify(flow, out _);

            Assert.IsNotNull(verdict, "SYN flood was not detected by the pre-filter.");
            Assert.AreEqual(AttackTypes.DoS, verdict.AttackType);
            Assert.AreEqual("prefilter_syn_flood", verdict.Reason);
        }

        [TestMethod]
        public void IcmpFlood_ShouldBeDetected()
        {
            var filter = new PreFilter(3);
            var flow = new FlowRecord
            {
                StartTime = DateTime.Now.AddSeconds(-5),
                LastSeenTime = DateTime.Now,
                Protocol = ProtocolNumbers.Icmp,
                DestinationPort = 0
            };

            for (int i = 0; i < 2000; i++)
            {
                flow.FwdPackets++;
                flow.FwdBytes += 64;
                flow.PacketSizeStats.Add(64);
            }

            var verdict = filter.Classify(flow, out _);

            Assert.IsNotNull(verdict, "ICMP flood was not detected by the pre-filter.");
            Assert.AreEqual(AttackTypes.DoS, verdict.AttackType);
            Assert.AreEqual("prefilter_icmp_flood", verdict.Reason);
        }

        [TestMethod]
        public void FloodWithReplyTraffic_ShouldStillBeDetected()
        {
            var filter = new PreFilter(3);
            var flow = new FlowRecord
            {
                StartTime = DateTime.Now.AddSeconds(-5),
                LastSeenTime = DateTime.Now,
                Protocol = ProtocolNumbers.Udp,
                DestinationPort = 80
            };

            for (int i = 0; i < 2000; i++)
            {
                flow.FwdPackets++;
                flow.FwdBytes += 1200;
                flow.PacketSizeStats.Add(1200);
            }
            flow.BwdPackets = 40;
            flow.BwdBytes = 48000;
            flow.PacketSizeStats.Add(1200);

            var verdict = filter.Classify(flow, out _);

            Assert.IsNotNull(verdict, "UDP flood with some reply traffic was not detected.");
            Assert.AreEqual("prefilter_udp_flood", verdict.Reason);
        }

        [TestMethod]
        public void ReversePacketVolume_ShouldReachAiWithoutSwappingSource()
        {
            var filter = new PreFilter(3);
            var flow = new FlowRecord
            {
                StartTime = DateTime.Now.AddSeconds(-5),
                LastSeenTime = DateTime.Now,
                Protocol = ProtocolNumbers.Udp,
                DestinationPort = 80
            };

            for (int i = 0; i < 2000; i++)
            {
                flow.BwdPackets++;
                flow.BwdBytes += 1200;
                flow.PacketSizeStats.Add(1200);
            }

            var verdict = filter.Classify(flow, out bool suspicious);

            Assert.IsNull(verdict);
            Assert.IsTrue(suspicious);
        }
    }
}

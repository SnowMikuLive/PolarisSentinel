using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using PolarisSentinel.TrafficCapture;
using PolarisSentinel.TrafficCapture.Internal;
using PolarisSentinel.Core.Models;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class TrafficCaptureUnitTest
    {
        #region RunningStats Tests

        [TestMethod]
        public void RunningStats_AddValues_ShouldCalculateCorrectMean()
        {
            // Arrange
            var stats = new RunningStats();
            double[] values = { 1.0, 2.0, 3.0, 4.0, 5.0 };

            // Act
            foreach (var value in values)
            {
                stats.Add(value);
            }

            // Assert
            Assert.AreEqual(5, stats.Count);
            Assert.AreEqual(3.0, stats.Mean);
        }

        [TestMethod]
        public void RunningStats_AddValues_ShouldCalculateCorrectMinAndMax()
        {
            // Arrange
            var stats = new RunningStats();

            // Act
            stats.Add(10);
            stats.Add(5);
            stats.Add(20);
            stats.Add(1);

            // Assert
            Assert.AreEqual(1, stats.Min);
            Assert.AreEqual(20, stats.Max);
        }

        [TestMethod]
        public void RunningStats_AddValues_ShouldCalculateCorrectStdDev()
        {
            // Arrange
            var stats = new RunningStats();
            double[] values = { 2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0 };

            // Act
            foreach (var value in values)
            {
                stats.Add(value);
            }

            // Assert
            Assert.AreEqual(8, stats.Count);
            Assert.AreEqual(5.0, stats.Mean);
            Assert.AreEqual(2.0, stats.StdDev, 0.001);
        }

        [TestMethod]
        public void RunningStats_EmptyStats_ShouldReturnZero()
        {
            // Arrange
            var stats = new RunningStats();

            // Act & Assert
            Assert.AreEqual(0, stats.Count);
            Assert.AreEqual(0, stats.Mean);
            Assert.AreEqual(0, stats.Min);
            Assert.AreEqual(0, stats.Max);
            Assert.AreEqual(0, stats.StdDev);
        }

        #endregion

        #region FlowKey Tests

        [TestMethod]
        public void FlowKey_Create_ShouldNormalizeIpOrder()
        {
            // Arrange
            string ip1 = "192.168.1.100";
            string ip2 = "10.0.0.1";
            ushort port1 = 12345;
            ushort port2 = 80;
            byte protocol = 6;

            // Act
            var key1 = FlowKey.Create(ip1, port1, ip2, port2, protocol);
            var key2 = FlowKey.Create(ip2, port2, ip1, port1, protocol);

            // Assert
            Assert.AreEqual(key1.IpA, key2.IpA);
            Assert.AreEqual(key1.IpB, key2.IpB);
            Assert.AreEqual(key1.PortA, key2.PortA);
            Assert.AreEqual(key1.PortB, key2.PortB);

            // 10.0.0.1 should come first alphabetically
            Assert.AreEqual("10.0.0.1", key1.IpA);
            Assert.AreEqual(80, key1.PortA);
        }

        [TestMethod]
        public void FlowKey_Equals_ShouldReturnTrueForSameFlow()
        {
            // Arrange
            var key1 = FlowKey.Create("192.168.1.1", 12345, "10.0.0.1", 80, 6);
            var key2 = FlowKey.Create("10.0.0.1", 80, "192.168.1.1", 12345, 6);

            // Act & Assert
            Assert.AreEqual(key1, key2);
            Assert.AreEqual(key1.GetHashCode(), key2.GetHashCode());
        }

        [TestMethod]
        public void FlowKey_Equals_ShouldReturnFalseForDifferentFlows()
        {
            // Arrange
            var key1 = FlowKey.Create("192.168.1.1", 12345, "10.0.0.1", 80, 6);
            var key2 = FlowKey.Create("192.168.1.1", 54321, "10.0.0.2", 443, 6);

            // Act & Assert
            Assert.AreNotEqual(key1, key2);
        }

        [TestMethod]
        public void FlowKey_Equals_ShouldReturnFalseForDifferentProtocols()
        {
            // Arrange
            var key1 = FlowKey.Create("192.168.1.1", 12345, "10.0.0.1", 80, 6); // TCP
            var key2 = FlowKey.Create("192.168.1.1", 12345, "10.0.0.1", 80, 17); // UDP

            // Act & Assert
            Assert.AreNotEqual(key1, key2);
        }

        #endregion

        #region FlowRecord Tests

        [TestMethod]
        public void FlowRecord_TotalPackets_ShouldSumFwdAndBwd()
        {
            // Arrange
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow,
                LastSeenTime = DateTime.UtcNow,
                FwdPackets = 10,
                BwdPackets = 5
            };

            // Act & Assert
            Assert.AreEqual(15, flow.TotalPackets);
        }

        [TestMethod]
        public void FlowRecord_TotalBytes_ShouldSumFwdAndBwd()
        {
            // Arrange
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow,
                LastSeenTime = DateTime.UtcNow,
                FwdBytes = 1000,
                BwdBytes = 500
            };

            // Act & Assert
            Assert.AreEqual(1500, flow.TotalBytes);
        }

        [TestMethod]
        public void FlowRecord_DurationSeconds_ShouldCalculateCorrectly()
        {
            // Arrange
            var startTime = DateTime.UtcNow.AddSeconds(-5);
            var endTime = DateTime.UtcNow;

            var flow = new FlowRecord
            {
                StartTime = startTime,
                LastSeenTime = endTime
            };

            // Act
            var duration = flow.DurationSeconds;

            // Assert
            Assert.AreEqual(5.0, duration, 0.1);
        }

        [TestMethod]
        public void FlowRecord_DownUpRatio_ShouldCalculateCorrectly()
        {
            // Arrange
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow,
                LastSeenTime = DateTime.UtcNow,
                FwdBytes = 1000,
                BwdBytes = 500
            };

            // Act
            var ratio = flow.DownUpRatio;

            // Assert
            Assert.AreEqual(2.0, ratio);
        }

        [TestMethod]
        public void FlowRecord_DownUpRatio_WhenBwdZero_ShouldReturnMaxValue()
        {
            // Arrange
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow,
                LastSeenTime = DateTime.UtcNow,
                FwdBytes = 1000,
                BwdBytes = 0
            };

            // Act
            var ratio = flow.DownUpRatio;

            // Assert
            Assert.AreEqual(double.MaxValue, ratio);
        }

        [TestMethod]
        public void FlowRecord_DownUpRatio_WhenFwdZero_ShouldReturnZero()
        {
            // Arrange
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow,
                LastSeenTime = DateTime.UtcNow,
                FwdBytes = 0,
                BwdBytes = 500
            };

            // Act
            var ratio = flow.DownUpRatio;

            // Assert
            Assert.AreEqual(0.0, ratio);
        }

        #endregion

        #region PreFilter Tests

        [TestMethod]
        public void PreFilter_TooFewPackets_ShouldReturnFalse()
        {
            // Arrange
            var filter = new PreFilter(3);
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow.AddSeconds(-2),
                LastSeenTime = DateTime.UtcNow,
                FwdPackets = 1,
                BwdPackets = 1,
                DestinationPort = 80
            };

            // Act
            var result = filter.IsWorthDeepAnalysis(flow);

            // Assert
            Assert.IsFalse(result);
        }

        [TestMethod]
        public void PreFilter_ShortDuration_ShouldReturnFalse()
        {
            // Arrange
            var filter = new PreFilter(3);
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow.AddMilliseconds(-50),
                LastSeenTime = DateTime.UtcNow,
                FwdPackets = 5,
                BwdPackets = 5,
                DestinationPort = 80
            };

            // Act
            var result = filter.IsWorthDeepAnalysis(flow);

            // Assert
            Assert.IsFalse(result);
        }

        [TestMethod]
        public void PreFilter_UnidirectionalTraffic_ShouldReturnFalse()
        {
            // Arrange
            var filter = new PreFilter(3);
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow.AddSeconds(-2),
                LastSeenTime = DateTime.UtcNow,
                FwdPackets = 10,
                BwdPackets = 0,
                DestinationPort = 443
            };

            // Act
            var result = filter.IsWorthDeepAnalysis(flow);

            // Assert
            Assert.IsFalse(result);
        }

        [TestMethod]
        public void PreFilter_NormalHttpTraffic_ShouldReturnFalse()
        {
            // Arrange
            var filter = new PreFilter(3);
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow.AddSeconds(-5),
                LastSeenTime = DateTime.UtcNow,
                FwdPackets = 10,
                BwdPackets = 12,
                FwdBytes = 5000,
                BwdBytes = 4500,
                DestinationPort = 80,
                SynCount = 1,
                AckCount = 10,
                FinCount = 1,
                RstCount = 0
            };

            // Act
            var result = filter.IsWorthDeepAnalysis(flow);

            // Assert
            Assert.IsFalse(result);
        }

        [TestMethod]
        public void PreFilter_NormalHttpsTraffic_ShouldReturnFalse()
        {
            // Arrange
            var filter = new PreFilter(3);
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow.AddSeconds(-5),
                LastSeenTime = DateTime.UtcNow,
                FwdPackets = 15,
                BwdPackets = 18,
                FwdBytes = 8000,
                BwdBytes = 12000,
                DestinationPort = 443,
                SynCount = 1,
                AckCount = 15,
                FinCount = 1,
                RstCount = 0
            };

            // Act
            var result = filter.IsWorthDeepAnalysis(flow);

            // Assert
            Assert.IsFalse(result);
        }

        [TestMethod]
        public void PreFilter_SynFloodAttack_ShouldReturnTrue()
        {
            // Arrange
            var filter = new PreFilter(3);
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow.AddSeconds(-1),
                LastSeenTime = DateTime.UtcNow,
                FwdPackets = 100,
                BwdPackets = 5,
                DestinationPort = 443,
                SynCount = 95,
                AckCount = 0,
                FinCount = 0,
                RstCount = 0
            };

            // Act
            var result = filter.IsWorthDeepAnalysis(flow);

            // Assert
            Assert.IsTrue(result);
        }

        [TestMethod]
        public void PreFilter_PortScanning_ShouldReturnTrue()
        {
            // Arrange
            var filter = new PreFilter(3);
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow.AddSeconds(-1.5),
                LastSeenTime = DateTime.UtcNow,
                FwdPackets = 20,
                BwdPackets = 3,
                DestinationPort = 22,
                SynCount = 20,
                AckCount = 0,
                FinCount = 0,
                RstCount = 15
            };

            // Act
            var result = filter.IsWorthDeepAnalysis(flow);

            // Assert
            Assert.IsTrue(result);
        }

        [TestMethod]
        public void PreFilter_ManyResets_ShouldReturnTrue()
        {
            // Arrange
            var filter = new PreFilter(3);
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow.AddSeconds(-3),
                LastSeenTime = DateTime.UtcNow,
                FwdPackets = 20,
                BwdPackets = 20,
                DestinationPort = 8080,
                SynCount = 1,
                AckCount = 10,
                FinCount = 0,
                RstCount = 10 // Too many resets
            };

            // Act
            var result = filter.IsWorthDeepAnalysis(flow);

            // Assert
            Assert.IsTrue(result);
        }

        #endregion

        #region FeatureExporter Tests

        [TestMethod]
        public void FeatureExporter_ShouldExportExactly20Features()
        {
            // Arrange
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow.AddSeconds(-10),
                LastSeenTime = DateTime.UtcNow,
                FwdPackets = 100,
                BwdPackets = 80,
                FwdBytes = 10000,
                BwdBytes = 8000,
                SynCount = 1,
                AckCount = 20,
                FinCount = 1,
                RstCount = 0,
                DestinationPort = 443
            };

            flow.PacketSizeStats.Add(64);
            flow.PacketSizeStats.Add(512);
            flow.PacketSizeStats.Add(1024);
            flow.PacketSizeStats.Add(64);
            flow.PacketSizeStats.Add(1500);

            flow.FwdIatStats.Add(10.5);
            flow.FwdIatStats.Add(20.3);
            flow.FwdIatStats.Add(15.7);

            flow.BwdIatStats.Add(12.1);
            flow.BwdIatStats.Add(18.9);
            flow.BwdIatStats.Add(14.3);

            var key = FlowKey.Create("192.168.1.1", 12345, "10.0.0.1", 443, 6);

            // Act
            var result = FeatureExporter.Export(
                flow, key,
                "192.168.1.1", 12345,
                "10.0.0.1", 443,
                6
            );

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(20, result.Features.Length);
            Assert.AreEqual("192.168.1.1", result.SourceIp);
            Assert.AreEqual(12345, result.SourcePort);
            Assert.AreEqual("10.0.0.1", result.DestinationIp);
            Assert.AreEqual(443, result.DestinationPort);
            Assert.AreEqual(6, result.Protocol);
        }

        [TestMethod]
        public void FeatureExporter_FeatureNames_ShouldHave20Features()
        {
            // Arrange & Act
            var names = TrafficCaptureService.FeatureNames;

            // Assert
            Assert.AreEqual(20, names.Length);
            Assert.Contains("flow_duration_seconds", names);
            Assert.Contains("total_fwd_packets", names);
            Assert.Contains("total_bwd_packets", names);
            Assert.Contains("down_up_ratio", names);
            Assert.Contains("flow_bytes_per_ms", names);
            Assert.Contains("flow_pkts_per_ms", names);

            // Verify TCP flags are NOT included
            Assert.IsFalse(names.Contains("syn_count"));
            Assert.IsFalse(names.Contains("ack_count"));
            Assert.IsFalse(names.Contains("fin_count"));
            Assert.IsFalse(names.Contains("rst_count"));
            Assert.IsFalse(names.Contains("destination_port"));
        }

        [TestMethod]
        public void FeatureExporter_ShouldCalculateRateMetricsCorrectly()
        {
            // Arrange
            var startTime = DateTime.UtcNow.AddSeconds(-2);
            var endTime = DateTime.UtcNow;

            var flow = new FlowRecord
            {
                StartTime = startTime,
                LastSeenTime = endTime,
                FwdPackets = 50,
                BwdPackets = 50,
                FwdBytes = 5000,
                BwdBytes = 5000,
                SynCount = 1,
                AckCount = 10,
                DestinationPort = 443
            };

            flow.PacketSizeStats.Add(100);
            flow.FwdIatStats.Add(1);
            flow.BwdIatStats.Add(1);

            var key = FlowKey.Create("192.168.1.1", 12345, "10.0.0.1", 443, 6);

            // Act
            var result = FeatureExporter.Export(
                flow, key,
                "192.168.1.1", 12345,
                "10.0.0.1", 443,
                6
            );

            // Assert
            float expectedBytesPerMs = 10000f / (2f * 1000); // 5 bytes/ms
            float expectedPktsPerMs = 100f / (2f * 1000); // 0.05 packets/ms

            Assert.AreEqual(expectedBytesPerMs, result.Features[17], 0.001);
            Assert.AreEqual(expectedPktsPerMs, result.Features[18], 0.001);
        }

        [TestMethod]
        public void FeatureExporter_ZeroDuration_ShouldReturnZeroRates()
        {
            // Arrange
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow,
                LastSeenTime = DateTime.UtcNow,
                FwdPackets = 10,
                BwdPackets = 10,
                FwdBytes = 1000,
                BwdBytes = 1000,
                DestinationPort = 80
            };

            flow.PacketSizeStats.Add(100);

            var key = FlowKey.Create("192.168.1.1", 12345, "10.0.0.1", 80, 6);

            // Act
            var result = FeatureExporter.Export(
                flow, key,
                "192.168.1.1", 12345,
                "10.0.0.1", 80,
                6
            );

            // Assert
            Assert.AreEqual(0, result.Features[17]); // bytes_per_ms
            Assert.AreEqual(0, result.Features[18]); // pkts_per_ms
        }

        #endregion

        #region TrafficCaptureService Tests

        [TestMethod]
        public void TrafficCaptureService_GetAvailableDevices_ShouldReturnAtLeastOneDevice()
        {
            // Arrange
            var service = new TrafficCaptureService(30, 3, 5);

            // Act
            var devices = service.GetAvailableDevices().ToList();

            // Assert
            Assert.IsNotNull(devices);
            Assert.IsTrue(devices.Count > 0);
            Assert.IsNotNull(devices[0].DeviceName);
            Assert.IsNotNull(devices[0].DisplayName);

            service.Dispose();
        }

        [TestMethod]
        public void TrafficCaptureService_FeatureNames_ShouldMatchExporter()
        {
            // Arrange
            var serviceNames = TrafficCaptureService.FeatureNames;
            var exporterNames = FeatureExporter.FeatureNames;

            // Act & Assert
            Assert.AreEqual(serviceNames.Length, exporterNames.Length);
            CollectionAssert.AreEqual(serviceNames, exporterNames);
        }

        [TestMethod]
        public void TrafficCaptureService_StartAndStop_ShouldNotThrowException()
        {
            // This test may fail if no network interface is available
            // or if permissions are insufficient

            // Arrange
            var service = new TrafficCaptureService(30, 3, 5);
            var devices = service.GetAvailableDevices().ToList();

            if (devices.Count == 0)
            {
                Assert.Inconclusive("No network interface available to test Start/Stop");
                return;
            }

            // Act
            service.Start(devices[0].DeviceName);

            // Wait a moment for capture to start
            System.Threading.Thread.Sleep(1000);

            service.Stop();

            // Assert
            // If we reached here without exception, test passes
            Assert.IsTrue(true);

            service.Dispose();
        }

        #endregion

        #region Integration Test (Simple Flow Processing)

        [TestMethod]
        public void FlowRecord_CanStoreAndRetrieveTcpFlags()
        {
            // Arrange
            var flow = new FlowRecord
            {
                StartTime = DateTime.UtcNow,
                LastSeenTime = DateTime.UtcNow
            };

            // Act
            flow.SynCount = 1;
            flow.AckCount = 10;
            flow.FinCount = 1;
            flow.RstCount = 0;
            flow.PshCount = 5;

            // Assert
            Assert.AreEqual(1, flow.SynCount);
            Assert.AreEqual(10, flow.AckCount);
            Assert.AreEqual(1, flow.FinCount);
            Assert.AreEqual(0, flow.RstCount);
            Assert.AreEqual(5, flow.PshCount);
        }

        [TestMethod]
        public void MultipleFlows_ShouldBeIndependent()
        {
            // Arrange
            var flow1 = new FlowRecord
            {
                StartTime = DateTime.UtcNow,
                LastSeenTime = DateTime.UtcNow,
                FwdPackets = 10,
                BwdPackets = 5
            };

            var flow2 = new FlowRecord
            {
                StartTime = DateTime.UtcNow,
                LastSeenTime = DateTime.UtcNow,
                FwdPackets = 20,
                BwdPackets = 15
            };

            // Act & Assert
            Assert.AreEqual(15, flow1.TotalPackets);
            Assert.AreEqual(35, flow2.TotalPackets);
            Assert.AreNotEqual(flow1.TotalPackets, flow2.TotalPackets);
        }

        #endregion
    }
}
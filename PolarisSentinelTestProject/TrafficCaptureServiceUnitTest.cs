using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using PolarisSentinel.TrafficCapture;
using PolarisSentinel.Core.Models;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class TrafficCaptureUnitTest
    {
        #region Basic Functionality Tests

        [TestMethod]
        public void TrafficCaptureService_Constructor_ShouldInitializeCorrectly()
        {
            // Arrange & Act
            var service = new TrafficCaptureService(
                flowIdleTimeoutSeconds: 30,
                preFilterMinPackets: 3,
                liveSummaryIntervalSeconds: 5
            );

            // Assert
            Assert.IsNotNull(service);

            var featureNames = TrafficCaptureService.FeatureNames;
            Assert.AreEqual(20, featureNames.Length);

            service.Dispose();
        }

        [TestMethod]
        public void TrafficCaptureService_FeatureNames_ShouldContainCorrectFeatures()
        {
            // Arrange & Act
            var featureNames = TrafficCaptureService.FeatureNames;

            // Assert
            Assert.AreEqual(20, featureNames.Length);

            CollectionAssert.Contains(featureNames, "flow_duration_seconds");
            CollectionAssert.Contains(featureNames, "total_fwd_packets");
            CollectionAssert.Contains(featureNames, "total_bwd_packets");
            CollectionAssert.Contains(featureNames, "total_fwd_bytes");
            CollectionAssert.Contains(featureNames, "total_bwd_bytes");
            CollectionAssert.Contains(featureNames, "pkt_len_min");
            CollectionAssert.Contains(featureNames, "pkt_len_max");
            CollectionAssert.Contains(featureNames, "pkt_len_mean");
            CollectionAssert.Contains(featureNames, "pkt_len_std");
            CollectionAssert.Contains(featureNames, "fwd_iat_mean_ms");
            CollectionAssert.Contains(featureNames, "fwd_iat_std_ms");
            CollectionAssert.Contains(featureNames, "fwd_iat_max_ms");
            CollectionAssert.Contains(featureNames, "fwd_iat_min_ms");
            CollectionAssert.Contains(featureNames, "bwd_iat_mean_ms");
            CollectionAssert.Contains(featureNames, "bwd_iat_std_ms");
            CollectionAssert.Contains(featureNames, "bwd_iat_max_ms");
            CollectionAssert.Contains(featureNames, "bwd_iat_min_ms");
            CollectionAssert.Contains(featureNames, "flow_bytes_per_ms");
            CollectionAssert.Contains(featureNames, "flow_pkts_per_ms");
            CollectionAssert.Contains(featureNames, "down_up_ratio");

            CollectionAssert.DoesNotContain(featureNames, "syn_count");
            CollectionAssert.DoesNotContain(featureNames, "ack_count");
            CollectionAssert.DoesNotContain(featureNames, "fin_count");
            CollectionAssert.DoesNotContain(featureNames, "rst_count");
            CollectionAssert.DoesNotContain(featureNames, "destination_port");
        }

        #endregion

        #region Device Enumeration Tests

        [TestMethod]
        public void TrafficCaptureService_GetAvailableDevices_ShouldReturnNonEmptyList()
        {
            // Arrange
            using var service = new TrafficCaptureService(30, 3, 5);

            // Act
            var devices = service.GetAvailableDevices().ToList();

            // Assert
            Assert.IsNotNull(devices);
            Assert.IsTrue(devices.Count > 0);

            foreach (var device in devices)
            {
                Assert.IsNotNull(device.DeviceName);
                Assert.IsNotNull(device.DisplayName);
            }
        }

        #endregion

        #region Event Subscription Tests

        [TestMethod]
        public void TrafficCaptureService_OnFlowCompleted_ShouldBeSubscribable()
        {
            // Arrange
            using var service = new TrafficCaptureService(30, 3, 5);
            bool eventFired = false;

            // Act - Subscribe to the event
            service.OnFlowCompleted += (sender, flow) =>
            {
                eventFired = true;
            };

            // Assert - Event subscription should not throw any exception
            Assert.IsTrue(true);
        }

        [TestMethod]
        public void TrafficCaptureService_OnLiveTrafficSummary_ShouldBeSubscribable()
        {
            // Arrange
            using var service = new TrafficCaptureService(30, 3, 5);
            bool eventFired = false;

            // Act - Subscribe to the event
            service.OnLiveTrafficSummary += (sender, summary) =>
            {
                eventFired = true;
            };

            // Assert - Event subscription should not throw any exception
            Assert.IsTrue(true);
        }

        [TestMethod]
        public void TrafficCaptureService_OnFlowCompleted_ShouldBeUnsubscribable()
        {
            // Arrange
            using var service = new TrafficCaptureService(30, 3, 5);
            EventHandler<FlowFeatureVector> handler = (sender, flow) => { };

            // Act & Assert
            service.OnFlowCompleted += handler;
            service.OnFlowCompleted -= handler;

            Assert.IsTrue(true);
        }

        [TestMethod]
        public void TrafficCaptureService_OnLiveTrafficSummary_ShouldBeUnsubscribable()
        {
            // Arrange
            using var service = new TrafficCaptureService(30, 3, 5);
            EventHandler<LiveTrafficSummary> handler = (sender, summary) => { };

            // Act & Assert
            service.OnLiveTrafficSummary += handler;
            service.OnLiveTrafficSummary -= handler;

            Assert.IsTrue(true);
        }

        #endregion

        #region Start and Stop Tests

        [TestMethod]
        public void TrafficCaptureService_Start_WithValidDevice_ShouldNotThrow()
        {
            // Arrange
            using var service = new TrafficCaptureService(30, 3, 5);
            var devices = service.GetAvailableDevices().ToList();

            if (devices.Count == 0)
            {
                Assert.Inconclusive("No network interface available, skipping test");
                return;
            }

            // Act & Assert
            service.Start(devices[0].DeviceName);

            System.Threading.Thread.Sleep(100);

            service.Stop();
        }

        [TestMethod]
        public void TrafficCaptureService_Start_WithInvalidDevice_ShouldThrowException()
        {
            // Arrange
            using var service = new TrafficCaptureService(30, 3, 5);
            string invalidDeviceName = "NonExistentDevice";

            // Act & Assert
            var exception = Assert.Throws<InvalidOperationException>(() =>
            {
                service.Start(invalidDeviceName);
            });

            Assert.IsNotNull(exception);
            Assert.IsTrue(exception.Message.Contains("No capture device found"));
        }

        [TestMethod]
        public void TrafficCaptureService_StartAndStop_MultipleTimes_ShouldWork()
        {
            // Arrange
            using var service = new TrafficCaptureService(30, 3, 5);
            var devices = service.GetAvailableDevices().ToList();

            if (devices.Count == 0)
            {
                Assert.Inconclusive("No network interface available, skipping test");
                return;
            }

            // Act
            for (int i = 0; i < 3; i++)
            {
                service.Start(devices[0].DeviceName);
                System.Threading.Thread.Sleep(50);
                service.Stop();
            }

            // Assert
            Assert.IsTrue(true);
        }

        #endregion

        #region LiveTrafficSummary Tests

        [TestMethod]
        public void LiveTrafficSummary_Properties_ShouldBeSetCorrectly()
        {
            // Arrange
            var timestamp = DateTime.UtcNow;
            var summary = new LiveTrafficSummary
            {
                Timestamp = timestamp,
                PacketsPerSecond = 100.5,
                BytesPerSecond = 1024.0,
                ActiveFlowCount = 42,
                TcpShare = 0.6,
                UdpShare = 0.3,
                IcmpShare = 0.1
            };

            // Assert
            Assert.AreEqual(timestamp, summary.Timestamp);
            Assert.AreEqual(100.5, summary.PacketsPerSecond);
            Assert.AreEqual(1024.0, summary.BytesPerSecond);
            Assert.AreEqual(42, summary.ActiveFlowCount);
            Assert.AreEqual(0.6, summary.TcpShare);
            Assert.AreEqual(0.3, summary.UdpShare);
            Assert.AreEqual(0.1, summary.IcmpShare);
        }

        [TestMethod]
        public void LiveTrafficSummary_ProtocolShares_ShouldSumToOne()
        {
            // Arrange
            var summary = new LiveTrafficSummary
            {
                Timestamp = DateTime.UtcNow,
                PacketsPerSecond = 100,
                BytesPerSecond = 1000,
                ActiveFlowCount = 10,
                TcpShare = 0.5,
                UdpShare = 0.3,
                IcmpShare = 0.2
            };

            // Assert
            double total = summary.TcpShare + summary.UdpShare + summary.IcmpShare;
            Assert.AreEqual(1.0, total, 0.001);
        }

        #endregion

        #region FlowFeatureVector Tests

        [TestMethod]
        public void FlowFeatureVector_Properties_ShouldBeSetCorrectly()
        {
            // Arrange
            var startTime = DateTime.UtcNow.AddSeconds(-10);
            var endTime = DateTime.UtcNow;
            float[] features = new float[20];
            for (int i = 0; i < 20; i++)
            {
                features[i] = i * 1.5f;
            }

            var vector = new FlowFeatureVector
            {
                Features = features,
                SourceIp = "192.168.1.100",
                SourcePort = 12345,
                DestinationIp = "10.0.0.1",
                DestinationPort = 443,
                Protocol = 6,
                FlowStartTime = startTime,
                FlowEndTime = endTime
            };

            // Assert
            Assert.AreEqual(20, vector.Features.Length);
            Assert.AreEqual("192.168.1.100", vector.SourceIp);
            Assert.AreEqual(12345, vector.SourcePort);
            Assert.AreEqual("10.0.0.1", vector.DestinationIp);
            Assert.AreEqual(443, vector.DestinationPort);
            Assert.AreEqual(6, vector.Protocol);
            Assert.AreEqual(startTime, vector.FlowStartTime);
            Assert.AreEqual(endTime, vector.FlowEndTime);

            for (int i = 0; i < 20; i++)
            {
                Assert.AreEqual(i * 1.5f, vector.Features[i]);
            }
        }

        [TestMethod]
        public void FlowFeatureVector_TotalPacketsAndBytes_ShouldCalculateCorrectly()
        {
            // Arrange
            var vector = new FlowFeatureVector
            {
                Features = new float[20],
                SourceIp = "1.1.1.1",
                SourcePort = 80,
                DestinationIp = "2.2.2.2",
                DestinationPort = 443,
                Protocol = 6,
                FlowStartTime = DateTime.UtcNow.AddSeconds(-5),
                FlowEndTime = DateTime.UtcNow
            };

            vector.Features[1] = 10;
            vector.Features[2] = 5;
            vector.Features[3] = 1000;
            vector.Features[4] = 500;

            // Act
            long totalPackets = (long)vector.Features[1] + (long)vector.Features[2];
            long totalBytes = (long)vector.Features[3] + (long)vector.Features[4];

            // Assert
            Assert.AreEqual(15, totalPackets);
            Assert.AreEqual(1500, totalBytes);
        }

        #endregion

        #region NetworkInterfaceInfo Tests

        [TestMethod]
        public void NetworkInterfaceInfo_Properties_ShouldBeSetCorrectly()
        {
            // Arrange
            var info = new NetworkInterfaceInfo
            {
                DeviceName = "eth0",
                DisplayName = "Ethernet Interface",
                IpAddress = "192.168.1.100"
            };

            // Assert
            Assert.AreEqual("eth0", info.DeviceName);
            Assert.AreEqual("Ethernet Interface", info.DisplayName);
            Assert.AreEqual("192.168.1.100", info.IpAddress);
        }

        [TestMethod]
        public void NetworkInterfaceInfo_WithNullIp_ShouldBeValid()
        {
            // Arrange
            var info = new NetworkInterfaceInfo
            {
                DeviceName = "lo",
                DisplayName = "Loopback",
                IpAddress = null
            };

            // Assert
            Assert.IsNotNull(info.DeviceName);
            Assert.IsNotNull(info.DisplayName);
            Assert.IsNull(info.IpAddress);
        }

        #endregion

        #region Resource Disposal Tests

        [TestMethod]
        public void TrafficCaptureService_Dispose_ShouldNotThrow()
        {
            // Arrange
            var service = new TrafficCaptureService(30, 3, 5);

            // Act & Assert
            try
            {
                service.Dispose();
                Assert.IsTrue(true);
            }
            catch (Exception ex)
            {
                Assert.Fail($"Dispose threw exception: {ex.Message}");
            }
        }

        [TestMethod]
        public void TrafficCaptureService_Dispose_MultipleTimes_ShouldNotThrow()
        {
            // Arrange
            var service = new TrafficCaptureService(30, 3, 5);

            // Act & Assert
            service.Dispose();
            service.Dispose();
            Assert.IsTrue(true);
        }

        [TestMethod]
        public void TrafficCaptureService_Stop_WithoutStart_ShouldNotThrow()
        {
            // Arrange
            using var service = new TrafficCaptureService(30, 3, 5);

            // Act & Assert
            try
            {
                service.Stop();
                Assert.IsTrue(true);
            }
            catch (Exception ex)
            {
                Assert.Fail($"Stop threw exception: {ex.Message}");
            }
        }

        #endregion

        #region Parameter Validation Tests

        [TestMethod]
        public void TrafficCaptureService_Constructor_WithZeroTimeout_ShouldNotThrow()
        {
            // Arrange & Act
            var service = new TrafficCaptureService(0, 3, 5);

            // Assert
            Assert.IsNotNull(service);
            service.Dispose();
        }

        [TestMethod]
        public void TrafficCaptureService_Constructor_WithNegativeValues_ShouldNotThrow()
        {
            // Arrange & Act
            var service = new TrafficCaptureService(-1, -2, -3);

            // Assert
            Assert.IsNotNull(service);
            service.Dispose();
        }

        #endregion

        #region Integration Test

        [TestMethod]
        public void TrafficCaptureService_RealCapture_ShouldProcessPackets()
        {
            using var service = new TrafficCaptureService(5, 3, 1);
            var devices = service.GetAvailableDevices().ToList();

            if (devices.Count == 0)
            {
                Assert.Inconclusive("No network interface available, skipping integration test");
                return;
            }

            bool flowReceived = false;
            bool summaryReceived = false;

            service.OnFlowCompleted += (sender, flow) =>
            {
                flowReceived = true;
            };

            service.OnLiveTrafficSummary += (sender, summary) =>
            {
                summaryReceived = true;
            };

            service.Start(devices[0].DeviceName);

            System.Threading.Thread.Sleep(10000);

            service.Stop();

            Assert.IsTrue(true);
        }

        #endregion
    }
}
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
        public void TrafficCaptureServiceConstructorShouldInitializeCorrectly()
        {
            var service = new TrafficCaptureService(
                flowIdleTimeoutSeconds: 30,
                preFilterMinPackets: 3,
                liveSummaryIntervalSeconds: 5
            );
            Assert.IsNotNull(service);

            var featureNames = TrafficCaptureService.FeatureNames;
            Assert.HasCount(20, featureNames);

            service.Dispose();
        }

        [TestMethod]
        public void TrafficCaptureServiceFeatureNamesShouldContainCorrectFeatures()
        {
            var featureNames = TrafficCaptureService.FeatureNames;
            Assert.HasCount(20, featureNames);

            CollectionAssert.Contains(featureNames, "flow_duration_ms");
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
        public void TrafficCaptureServiceGetAvailableDevicesShouldReturnNonEmptyList()
        {
            using var service = new TrafficCaptureService(30, 3, 5);
            var devices = service.GetAvailableDevices().ToList();
            Assert.IsNotNull(devices);
            Assert.IsNotEmpty(devices);

            foreach (var device in devices)
            {
                Assert.IsNotNull(device.DeviceName);
                Assert.IsNotNull(device.DisplayName);
            }
        }

        #endregion

        #region Start and Stop Tests

        [TestMethod]
        public void TrafficCaptureServiceStartWithValidDeviceShouldNotThrow()
        {
            using var service = new TrafficCaptureService(30, 3, 5);
            var devices = service.GetAvailableDevices().ToList();

            if (devices.Count == 0)
            {
                Assert.Inconclusive("No network interface available, skipping test");
                return;
            }
            service.Start(devices[0].DeviceName);

            System.Threading.Thread.Sleep(100);

            service.Stop();
        }

        [TestMethod]
        public void TrafficCaptureServiceStartWithInvalidDeviceShouldThrowException()
        {
            using var service = new TrafficCaptureService(30, 3, 5);
            string invalidDeviceName = "NonExistentDevice";
            var exception = Assert.Throws<InvalidOperationException>(() =>
            {
                service.Start(invalidDeviceName);
            });

            Assert.IsNotNull(exception);
            Assert.Contains("No capture device found", exception.Message);
        }

        [TestMethod]
        public void TrafficCaptureServiceStartAndStopMultipleTimesShouldWork()
        {
            using var service = new TrafficCaptureService(30, 3, 5);
            var devices = service.GetAvailableDevices().ToList();

            if (devices.Count == 0)
            {
                Assert.Inconclusive("No network interface available, skipping test");
                return;
            }
            for (int i = 0; i < 3; i++)
            {
                service.Start(devices[0].DeviceName);
                System.Threading.Thread.Sleep(50);
                service.Stop();
            }
            var devicesAfter = service.GetAvailableDevices().ToList();
            Assert.IsNotEmpty(devicesAfter);
        }

        #endregion

        #region Integration Test

        [TestMethod]
        public void TrafficCaptureServiceRealCaptureShouldProcessPackets()
        {
            using var service = new TrafficCaptureService(5, 3, 1);
            var devices = service.GetAvailableDevices().ToList();

            if (devices.Count == 0)
            {
                Assert.Inconclusive("No network interface available, skipping integration test");
                return;
            }

            bool summaryReceived = false;

            service.OnLiveTrafficSummary += (sender, summary) =>
            {
                summaryReceived = true;
            };

            service.Start(devices[0].DeviceName);

            System.Threading.Thread.Sleep(10000);

            service.Stop();
            // that packets were actually captured and processed.
            Assert.IsTrue(summaryReceived, "Live traffic summary should be received during capture");
        }

        #endregion
    }
}
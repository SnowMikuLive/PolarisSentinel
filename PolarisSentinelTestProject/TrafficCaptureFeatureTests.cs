using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using SharpPcap;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PacketDotNet;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Core.Services;
using PolarisSentinel.TrafficCapture;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class TrafficCaptureFeatureTests
{
    public TestContext TestContext { get; set; }

    [TestMethod]
    [DataRow(false, false)]
    [DataRow(false, true)]
    [DataRow(true, false)]
    [DataRow(true, true)]
    public async Task FlowFeatures_CountTransportPayloadBytes(bool udp, bool ipv6)
    {
        using var capture = new TrafficCaptureService(
            flowIdleTimeoutSeconds: 1,
            thresholds: DetectionThresholds.High,
            detection: new DetectionRuntimeState(heuristicEnabled: false));
        var completed = new TaskCompletionSource<FlowFeatureVector>(TaskCreationOptions.RunContinuationsAsynchronously);
        capture.OnFlowCompleted += (_, flow) => completed.TrySetResult(flow);
        var start = new DateTime(2026, 10, 16, 12, 0, 0);

        capture.ProcessPacket(CreatePacket(udp, ipv6, payloadLength: 6), start);
        capture.ProcessPacket(CreatePacket(udp, ipv6, payloadLength: 0), start.AddMilliseconds(1));
        capture.ProcessPacket(CreatePacket(udp, ipv6, payloadLength: 12, reverse: true), start.AddMilliseconds(2));
        capture.ExpireIdleFlows(start.AddSeconds(2));

        var flow = await completed.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.CancellationToken);

        CollectionAssert.AreEqual(new float[]
        {
            2, 2, 1, 6, 12, 0, 12, 6, 6,
            1, 0, 1, 1, 0, 0, 0, 0, 9, 1.5f, 0.5f
        }, flow.Features);
    }

    private static Packet CreatePacket(bool udp, bool ipv6, int payloadLength, bool reverse = false)
    {
        var remote = IPAddress.Parse(ipv6 ? "2001:db8::1" : "203.0.113.1");
        var local = IPAddress.Parse(ipv6 ? "2001:db8::2" : "192.0.2.2");
        var source = reverse ? local : remote;
        var destination = reverse ? remote : local;
        ushort sourcePort = reverse ? (ushort)443 : (ushort)50000;
        ushort destinationPort = reverse ? (ushort)50000 : (ushort)443;
        Packet transport = udp
            ? new UdpPacket(sourcePort, destinationPort)
            : new TcpPacket(sourcePort, destinationPort) { Acknowledgment = true };
        transport.PayloadData = new byte[payloadLength];
        IPPacket ip = ipv6 ? new IPv6Packet(source, destination) : new IPv4Packet(source, destination);
        ip.PayloadPacket = transport;

        return Packet.ParsePacket(LinkLayers.Raw, ip.Bytes);
    }

    [TestMethod]
    public void AddressChange_RefreshesSelectedInterfaceWithoutRestartingCapture()
    {
        var network = NetworkInterface.GetAllNetworkInterfaces().First(n =>
            n.GetIPProperties().UnicastAddresses.Count > 0);
        using var capture = new TrafficCaptureService(1, DetectionThresholds.High);
        var device = DispatchProxy.Create<ICaptureDevice, CaptureDeviceProxy>();
        ((CaptureDeviceProxy)(object)device).DeviceName = @"\Device\NPF_" + network.Id;
        var type = typeof(TrafficCaptureService);
        type.GetField("_device", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(capture, device);
        type.GetField("_localAddresses", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(capture,
            new HashSet<string> { "192.0.2.99" });

        type.GetMethod("OnNetworkAddressChanged", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(capture, new object?[] { null, EventArgs.Empty });

        var addresses = (HashSet<string>)type.GetField("_localAddresses", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(capture)!;
        CollectionAssert.AreEquivalent(network.GetIPProperties().UnicastAddresses.Select(a => a.Address.ToString()).ToArray(), addresses.ToArray());
        Assert.DoesNotContain("192.0.2.99", addresses);
    }

    public class CaptureDeviceProxy : DispatchProxy
    {
        public string DeviceName { get; set; } = string.Empty;
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) =>
            targetMethod?.Name == "get_Name" ? DeviceName : null;
    }
}

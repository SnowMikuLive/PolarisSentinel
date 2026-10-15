using System.Net;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PacketDotNet;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Core.Services;
using PolarisSentinel.TrafficCapture;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class TrafficCaptureFeatureTests
{
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

        var flow = await completed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        // CIC payload lengths [6, 0, 12]: forward bytes 6, backward bytes 12,
        // sample standard deviation 6, and total 18 bytes over 2 milliseconds.
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
}

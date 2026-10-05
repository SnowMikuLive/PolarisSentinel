using System.Net;
using System.Reflection;
using PacketDotNet;
using PolarisSentinel.Core.Models;
using PolarisSentinel.TrafficCapture;
using PolarisSentinel.TrafficCapture.Internal;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class CaptureFeatureTests
{
    [TestMethod]
    [DataRow("203.0.113.66", "192.168.1.10")]
    [DataRow("192.168.1.10", "203.0.113.66")]
    [DataRow("127.0.0.1", "127.0.0.1")]
    public void ReplyPackets_ShouldKeepFirstSenderAndFeatureValues(string source, string destination)
    {
        using var service = new TrafficCaptureService(1, 3);
        var completed = new List<FlowFeatureVector>();
        using var completedSignal = new ManualResetEventSlim();
        service.OnFlowCompleted += (_, flow) => { completed.Add(flow); completedSignal.Set(); };
        var start = new DateTime(2026, 9, 24);
        int[] times = { 0, 10, 30, 50, 90, 110, 150 };

        for (int i = 0; i < times.Length; i++)
        {
            bool forward = i % 2 == 0;
            var packet = forward
                ? Tcp(source, 50000, destination, 22, 60 + i * 20)
                : Tcp(destination, 22, source, 50000, 60 + i * 20);
            service.ProcessPacket(packet, start.AddMilliseconds(times[i]));
        }
        service.ExpireIdleFlows(start.AddSeconds(2));

        Assert.IsTrue(completedSignal.Wait(TimeSpan.FromSeconds(2)));
        Assert.HasCount(1, completed);
        var result = completed[0];
        Assert.AreEqual(source, result.SourceIp);
        Assert.AreEqual(destination, result.DestinationIp);
        Assert.AreEqual((ushort)50000, result.SourcePort);
        Assert.AreEqual((ushort)22, result.DestinationPort);
        Assert.AreEqual(7L, result.TotalPackets);
        Assert.AreEqual(560L, result.TotalBytes);
        Assert.IsTrue(result.PreFilterVerdict?.IsSuspicious ?? false);
        // 每个 IPv4/TCP 包去掉 40 字节头后，手算 payload、样本标准差、IAT 和速率。
        // Subtract each 40-byte IPv4/TCP header, then calculate payload statistics, IATs and rates.
        float[] expected = { 150, 4, 3, 320, 240, 20, 140, 80, (float)Math.Sqrt(11200.0 / 6),
            50, (float)Math.Sqrt(300), 60, 30, 50, (float)Math.Sqrt(200), 60, 40,
            560f / 150, 7f / 150, 0.75f };
        Assert.HasCount(20, result.Features);
        for (int i = 0; i < expected.Length; i++)
            Assert.AreEqual(expected[i], result.Features[i], 0.0001f, TrafficCaptureService.FeatureNames[i]);
    }

    [TestMethod]
    [DataRow(80)]
    [DataRow(22)]
    [DataRow(21)]
    public void ShortConnection_ShouldBeDroppedByCurrentPreFilter(int port)
    {
        using var service = new TrafficCaptureService(1, 3);
        using var completedSignal = new ManualResetEventSlim();
        service.OnFlowCompleted += (_, _) => completedSignal.Set();
        var start = new DateTime(2026, 9, 24);
        service.ProcessPacket(Tcp("203.0.113.66", 50000, "192.168.1.10", (ushort)port, 60, syn: true), start);
        service.ProcessPacket(Tcp("192.168.1.10", (ushort)port, "203.0.113.66", 50000, 60), start.AddMilliseconds(1));
        service.ExpireIdleFlows(start.AddSeconds(2));

        Assert.IsFalse(completedSignal.Wait(TimeSpan.FromMilliseconds(100)));
    }

    [TestMethod]
    [DataRow(40)]
    [DataRow(60)]
    public void SynFlood_ShouldKeepAttackerAddressAndCountPayload(int packetSize)
    {
        using var service = new TrafficCaptureService(1, 3);
        FlowFeatureVector? result = null;
        using var completedSignal = new ManualResetEventSlim();
        service.OnFlowCompleted += (_, flow) => { result = flow; completedSignal.Set(); };
        var start = new DateTime(2026, 9, 24);
        for (int i = 0; i < 12; i++)
            service.ProcessPacket(Tcp("203.0.113.66", 50000, "192.168.1.10", 80, packetSize, syn: true), start.AddMilliseconds(i * 20));
        service.ExpireIdleFlows(start.AddSeconds(2));

        Assert.IsTrue(completedSignal.Wait(TimeSpan.FromSeconds(2)));
        Assert.IsNotNull(result);
        // Single-flow signatures are forwarded as Suspicious for AI confirmation, not blocked outright.
        Assert.IsTrue(result.PreFilterVerdict?.IsSuspicious ?? false);
        Assert.IsFalse(result.PreFilterVerdict?.IsKnownAttack ?? true);
        Assert.AreEqual("203.0.113.66", result.SourceIp);
        Assert.AreEqual(12f, result.Features[1]);
        Assert.AreEqual(0f, result.Features[2]);
        Assert.AreEqual(12L * (packetSize - 40), result.TotalBytes);
        Assert.AreEqual(packetSize - 40f, result.Features[5]);
        Assert.AreEqual(packetSize - 40f, result.Features[6]);
        Assert.IsTrue(result.Features.All(float.IsFinite));
    }

    [TestMethod]
    [DataRow(28)]
    [DataRow(48)]
    public void UdpFlow_ShouldCountPayloadWhileLiveSummaryCountsIpBytes(int packetSize)
    {
        using var service = new TrafficCaptureService(1, 3);
        FlowFeatureVector? result = null;
        LiveTrafficSummary? summary = null;
        using var completedSignal = new ManualResetEventSlim();
        service.OnFlowCompleted += (_, flow) => { result = flow; completedSignal.Set(); };
        service.OnLiveTrafficSummary += (_, live) => summary = live;
        var start = new DateTime(2026, 9, 24);

        for (int i = 0; i < 6; i++)
            service.ProcessPacket(Udp("203.0.113.66", 50000, "192.168.1.10", 1234, packetSize), start.AddMilliseconds(i * 40));
        service.ExpireIdleFlows(start.AddSeconds(2));
        typeof(TrafficCaptureService).GetMethod("EmitLiveSummary", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(service, null);

        Assert.IsTrue(completedSignal.Wait(TimeSpan.FromSeconds(2)));
        Assert.IsNotNull(result);
        Assert.AreEqual(6L, result.TotalPackets);
        Assert.AreEqual(6L * (packetSize - 28), result.TotalBytes);
        Assert.AreEqual(6f * (packetSize - 28), result.Features[3]);
        Assert.AreEqual(packetSize - 28f, result.Features[5]);
        Assert.AreEqual(packetSize - 28f, result.Features[6]);
        Assert.AreEqual(packetSize - 28f, result.Features[7]);
        Assert.AreEqual(6f * (packetSize - 28) / 200, result.Features[17], 0.0001f);
        Assert.IsTrue(result.Features.All(float.IsFinite));
        Assert.IsNotNull(summary);
        Assert.AreEqual(6L * packetSize, summary.Bytes);
    }

    [TestMethod]
    public void SinglePacket_ShouldExportFiniteFeatures()
    {
        var start = new DateTime(2026, 9, 24);
        var flow = new FlowRecord { StartTime = start, LastSeenTime = start, FwdPackets = 1, FwdBytes = 60 };
        flow.PacketSizeStats.Add(60);
        var key = FlowKey.Create("203.0.113.66", 50000, "192.168.1.10", 80, 6);
        var result = FeatureExporter.Export(flow, key, "203.0.113.66", 50000, "192.168.1.10", 80, 6);

        Assert.IsNotNull(result);
        Assert.IsTrue(result.Features.All(float.IsFinite));
        Assert.AreEqual(0f, result.Features[0]);
        Assert.AreEqual(0f, result.Features[17]);
        Assert.AreEqual(0f, result.Features[18]);
        Assert.AreEqual(0f, result.Features[19]);
    }

    [TestMethod]
    public void NoForwardPackets_ShouldExportZeroRatio()
    {
        var start = new DateTime(2026, 9, 24);
        var flow = new FlowRecord { StartTime = start, LastSeenTime = start, BwdPackets = 1 };
        var key = FlowKey.Create("203.0.113.66", 50000, "192.168.1.10", 80, 6);
        var result = FeatureExporter.Export(flow, key, "203.0.113.66", 50000, "192.168.1.10", 80, 6);
        Assert.AreEqual(0f, result.Features[19]);
        Assert.IsTrue(result.Features.All(float.IsFinite));
    }

    // 构造并解析样本包，不依赖 Npcap，也不发送网络流量。
    // Build and parse sample packets without Npcap or network traffic.
    private static Packet Tcp(string source, ushort sourcePort, string destination, ushort destinationPort, int size, bool syn = false)
    {
        var packet = new IPv4Packet(IPAddress.Parse(source), IPAddress.Parse(destination))
        {
            PayloadPacket = new TcpPacket(sourcePort, destinationPort)
            {
                PayloadData = new byte[size - 40],
                Synchronize = syn
            },
            TotalLength = (ushort)size
        };
        return Packet.ParsePacket(LinkLayers.Raw, packet.Bytes);
    }

    private static Packet Udp(string source, ushort sourcePort, string destination, ushort destinationPort, int size)
    {
        var packet = new IPv4Packet(IPAddress.Parse(source), IPAddress.Parse(destination))
        {
            PayloadPacket = new UdpPacket(sourcePort, destinationPort)
            {
                PayloadData = new byte[size - 28]
            },
            TotalLength = (ushort)size
        };
        return Packet.ParsePacket(LinkLayers.Raw, packet.Bytes);
    }
}

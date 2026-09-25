using System.Collections.Concurrent;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;


namespace PolarisSentinel.TrafficCapture;

public sealed class TrafficCaptureService : ITrafficCaptureService, IDisposable
{
    private readonly ConcurrentDictionary<Internal.FlowKey, Internal.FlowRecord> _flows = new();
    private readonly Internal.PreFilter _preFilter;

    private readonly int _flowIdleTimeoutSeconds;
    private readonly System.Threading.Timer _expiryTimer;
    private readonly System.Threading.Timer _liveSummaryTimer;
    public static string[] FeatureNames => Internal.FeatureExporter.FeatureNames;
    private ICaptureDevice? _device;

    // Fast-path counters, reset every time OnLiveTrafficSummary fires.
    private long _packetsSinceLastTick;
    private long _bytesSinceLastTick;
    private long _tcpSinceLastTick;
    private long _udpSinceLastTick;
    private long _icmpSinceLastTick;
    private DateTime _lastTickTime = DateTime.Now;

    private const int MaxFlowCount = 100000;

    public event EventHandler<FlowFeatureVector>? OnFlowCompleted;
    public event EventHandler<LiveTrafficSummary>? OnLiveTrafficSummary;


    // From PolicySettings.FlowIdleTimeoutSeconds. A flow with no new packets for this many seconds is considered finished and exported.

    public TrafficCaptureService(
        int flowIdleTimeoutSeconds,
        int preFilterMinPackets,
        int liveSummaryIntervalSeconds = 5)
    {
        _flowIdleTimeoutSeconds = flowIdleTimeoutSeconds;
        _preFilter = new Internal.PreFilter(preFilterMinPackets);

        // Both timers are created suspended (Timeout.Infinite due time) and
        // only actually start ticking once Start(deviceName) is called.
        _expiryTimer = new System.Threading.Timer(_ => ExpireIdleFlows(DateTime.Now), null, Timeout.Infinite, Timeout.Infinite);
        _liveSummaryTimer = new System.Threading.Timer(_ => EmitLiveSummary(), null, Timeout.Infinite, Timeout.Infinite);
    }

    public IEnumerable<NetworkInterfaceInfo> GetAvailableDevices()
    {
        foreach (var device in CaptureDeviceList.Instance)
        {
            string? ip = null;
            if (device is LibPcapLiveDevice liveDevice)
            {
                ip = liveDevice.Addresses
                    .Select(a => a.Addr?.ipAddress?.ToString())
                    .FirstOrDefault(a => a is not null);
            }

            yield return new NetworkInterfaceInfo
            {
                DeviceName = device.Name,
                DisplayName = device.Description ?? device.Name,
                IpAddress = ip
            };
        }
    }

    public void Start(string deviceName)
    {
        _device = CaptureDeviceList.Instance
            .FirstOrDefault(d => d.Name == deviceName)
            ?? throw new InvalidOperationException($"No capture device found with name '{deviceName}'.");

        _device.OnPacketArrival += OnPacketArrival;
        _device.Open(DeviceModes.Promiscuous, 1000);
        _device.StartCapture();

        // Check for idle flows every 5 seconds regardless of the configured timeout itself, so expiry is responsive without busy-polling.
        _expiryTimer.Change(TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        _liveSummaryTimer.Change(TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
    }

    public void Stop()
    {
        _expiryTimer.Change(Timeout.Infinite, Timeout.Infinite);
        _liveSummaryTimer.Change(Timeout.Infinite, Timeout.Infinite);

        if (_device is not null)
        {
            _device.StopCapture();
            _device.OnPacketArrival -= OnPacketArrival;
            _device.Close();
            _device = null;
        }
    }

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        RawCapture rawPacket = e.GetPacket();
        Packet parsed = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        ProcessPacket(parsed, rawPacket.Timeval.Date.ToLocalTime());
    }

    // 实时抓包和样本测试使用同一段聚合代码。
    // Live capture and packet tests share this aggregation code.
    internal void ProcessPacket(Packet parsed, DateTime now)
    {
        IPPacket? ipPacket = parsed.Extract<IPPacket>();
        if (ipPacket is null) return; // not IPv4/IPv6, nothing we track

        TcpPacket? tcpPacket = parsed.Extract<TcpPacket>();
        UdpPacket? udpPacket = parsed.Extract<UdpPacket>();

        string srcIp = ipPacket.SourceAddress.ToString();
        string dstIp = ipPacket.DestinationAddress.ToString();
        ushort srcPort = tcpPacket?.SourcePort ?? udpPacket?.SourcePort ?? 0;
        ushort dstPort = tcpPacket?.DestinationPort ?? udpPacket?.DestinationPort ?? 0;
        byte protocol = (byte)ipPacket.Protocol;
        int packetSize = ipPacket.TotalLength;

        UpdateFastPathCounters(packetSize, protocol);

        var key = Internal.FlowKey.Create(srcIp, srcPort, dstIp, dstPort, protocol);
        var flow = _flows.GetOrAdd(key, _ => new Internal.FlowRecord
        {
            StartTime = now,
            LastSeenTime = now,
            SourceIp = srcIp,
            SourcePort = srcPort,
            DestinationIp = dstIp,
            Protocol = protocol,
            DestinationPort = dstPort
        });

        bool isForward = srcIp == flow.SourceIp && srcPort == flow.SourcePort;

        lock (flow) // packets for the same flow can arrive back-to-back on the capture thread
        {
            flow.PacketSizeStats.Add(packetSize);

            if (isForward)
            {
                flow.FwdPackets++;
                flow.FwdBytes += packetSize;
                if (flow.LastFwdPacketTime is { } lastFwd)
                    flow.FwdIatStats.Add((now - lastFwd).TotalMilliseconds);
                flow.LastFwdPacketTime = now;
            }
            else
            {
                flow.BwdPackets++;
                flow.BwdBytes += packetSize;
                if (flow.LastBwdPacketTime is { } lastBwd)
                    flow.BwdIatStats.Add((now - lastBwd).TotalMilliseconds);
                flow.LastBwdPacketTime = now;
            }

            if (tcpPacket is not null)
            {
                if (tcpPacket.Synchronize) flow.SynCount++;
                if (tcpPacket.Acknowledgment) flow.AckCount++;
                if (tcpPacket.Finished) flow.FinCount++;
                if (tcpPacket.Reset) flow.RstCount++;
                if (tcpPacket.Push) flow.PshCount++;
            }

            flow.LastSeenTime = now;
        }
    }

    private void UpdateFastPathCounters(int packetSize, byte protocol)
    {
        Interlocked.Increment(ref _packetsSinceLastTick);
        Interlocked.Add(ref _bytesSinceLastTick, packetSize);

        switch (protocol)
        {
            case Core.Constants.ProtocolNumbers.Tcp: Interlocked.Increment(ref _tcpSinceLastTick); break;
            case Core.Constants.ProtocolNumbers.Udp: Interlocked.Increment(ref _udpSinceLastTick); break;
            case Core.Constants.ProtocolNumbers.Icmp: Interlocked.Increment(ref _icmpSinceLastTick); break;
        }
    }

    internal void ExpireIdleFlows(DateTime now)
    {
        var timeout = TimeSpan.FromSeconds(_flowIdleTimeoutSeconds);


        foreach (var (key, flow) in _flows)
        {
            bool isIdle;
            lock (flow) { isIdle = now - flow.LastSeenTime > timeout; }
            if (!isIdle) continue;

            if (!_flows.TryRemove(key, out _)) continue; // another thread already removed it

            // 规则命中时携带结果，其余非空流交给模型。
            // Emit rule verdicts; send other nonempty flows to the model.
            var verdict = _preFilter.Classify(flow, out bool suspicious);
            if (verdict is null && !suspicious) continue;

            var featureVector = Internal.FeatureExporter.Export(
                flow, key,
                sourceIp: flow.SourceIp, sourcePort: flow.SourcePort,
                destinationIp: flow.DestinationIp, destinationPort: (ushort)flow.DestinationPort,
                protocol: key.Protocol);

            OnFlowCompleted?.Invoke(this, new FlowFeatureVector
            {
                Features = featureVector.Features,
                SourceIp = featureVector.SourceIp,
                SourcePort = featureVector.SourcePort,
                DestinationIp = featureVector.DestinationIp,
                DestinationPort = featureVector.DestinationPort,
                Protocol = featureVector.Protocol,
                FlowStartTime = featureVector.FlowStartTime,
                FlowEndTime = featureVector.FlowEndTime,
                TotalPackets = featureVector.TotalPackets,
                TotalBytes = featureVector.TotalBytes,
                PreFilterVerdict = verdict
            });
        }
    }

    private void EmitLiveSummary()
    {
        DateTime now = DateTime.Now;
        double elapsedSeconds = Math.Max((now - _lastTickTime).TotalSeconds, 0.001);

        long packets = Interlocked.Exchange(ref _packetsSinceLastTick, 0);
        long bytes = Interlocked.Exchange(ref _bytesSinceLastTick, 0);
        long tcp = Interlocked.Exchange(ref _tcpSinceLastTick, 0);
        long udp = Interlocked.Exchange(ref _udpSinceLastTick, 0);
        long icmp = Interlocked.Exchange(ref _icmpSinceLastTick, 0);
        long total = Math.Max(tcp + udp + icmp, 1);

        _lastTickTime = now;

        OnLiveTrafficSummary?.Invoke(this, new LiveTrafficSummary
        {
            Timestamp = now,
            PacketsPerSecond = packets / elapsedSeconds,
            BytesPerSecond = bytes / elapsedSeconds,
            ActiveFlowCount = _flows.Count,
            TcpShare = (double)tcp / total,
            UdpShare = (double)udp / total,
            IcmpShare = (double)icmp / total
        });
    }

    public void Dispose()
    {
        Stop();
        _expiryTimer.Dispose();
        _liveSummaryTimer.Dispose();
    }
}

using System.Collections.Concurrent;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Core.Services;


namespace PolarisSentinel.TrafficCapture;

public sealed class TrafficCaptureService : ITrafficCaptureService, IDisposable
{
    private readonly ConcurrentDictionary<Internal.FlowKey, Internal.FlowRecord> _flows = new();
    private readonly PreFilter _preFilter;
    private readonly SourceBehaviorTracker _behavior;
    private readonly DetectionRuntimeState? _detection;

    private bool HeuristicEnabled => _detection?.HeuristicEnabled ?? true;

    private readonly int _flowIdleTimeoutSeconds;
    private readonly System.Threading.Timer _expiryTimer;
    private readonly System.Threading.Timer _liveSummaryTimer;
    private ICaptureDevice? _device;

    private readonly object _deviceLock = new();

    private List<NetworkInterfaceInfo> _cachedDevices = new();

    private readonly HashSet<string> _localAddresses = new(StringComparer.OrdinalIgnoreCase);

    private long _packetsSinceLastTick;
    private long _bytesSinceLastTick;
    private long _tcpSinceLastTick;
    private long _udpSinceLastTick;
    private long _icmpSinceLastTick;
    private DateTime _lastTickTime = DateTime.Now;

    private const int MaxFlowCount = 100000;

    private static readonly TimeSpan ExpiryTimeBudget = TimeSpan.FromMilliseconds(200);

    private static readonly TimeSpan BehaviorWindow = TimeSpan.FromSeconds(10);

    private static readonly TimeSpan BehaviorCooldown = TimeSpan.FromSeconds(5);

    public event EventHandler<FlowFeatureVector>? OnFlowCompleted;
    public event EventHandler<LiveTrafficSummary>? OnLiveTrafficSummary;

    public TrafficCaptureService(
        int flowIdleTimeoutSeconds,
        DetectionThresholds thresholds,
        int liveSummaryIntervalSeconds = 5,
        DetectionRuntimeState? detection = null)
    {
        _flowIdleTimeoutSeconds = flowIdleTimeoutSeconds;
        _preFilter = new PreFilter(thresholds);
        _behavior = new SourceBehaviorTracker(BehaviorWindow, thresholds, BehaviorCooldown);
        _detection = detection;

        _expiryTimer = new System.Threading.Timer(_ => SafeExpireIdleFlows(), null, Timeout.Infinite, Timeout.Infinite);
        _liveSummaryTimer = new System.Threading.Timer(_ => SafeEmitLiveSummary(), null, Timeout.Infinite, Timeout.Infinite);
    }

    public IEnumerable<NetworkInterfaceInfo> GetAvailableDevices()
    {
        return SnapshotDevices();
    }

    private List<NetworkInterfaceInfo> SnapshotDevices()
    {
        lock (_deviceLock)
        {
            var fresh = EnumerateDevices();
            if (fresh.Count >= _cachedDevices.Count)
            {
                _cachedDevices = fresh;
            }

            return _cachedDevices.Count > 0 ? new List<NetworkInterfaceInfo>(_cachedDevices) : fresh;
        }
    }

    private static List<NetworkInterfaceInfo> EnumerateDevices()
    {
        try
        {
            CaptureDeviceList.Instance.Refresh();
        }
        catch (Exception)
        {
        }

        var devices = new List<NetworkInterfaceInfo>();

        try
        {
            foreach (var device in CaptureDeviceList.Instance)
            {
                try
                {
                    string? ip = null;
                    if (device is LibPcapLiveDevice liveDevice)
                    {
                        ip = liveDevice.Addresses
                            .Select(a => a.Addr?.ipAddress?.ToString())
                            .FirstOrDefault(a => a is not null);
                    }

                    devices.Add(new NetworkInterfaceInfo
                    {
                        DeviceName = device.Name,
                        DisplayName = device.Description ?? device.Name,
                        IpAddress = ip
                    });
                }
                catch (Exception)
                {
                    devices.Add(new NetworkInterfaceInfo
                    {
                        DeviceName = device.Name,
                        DisplayName = device.Description ?? device.Name,
                        IpAddress = null
                    });
                }
            }
        }
        catch (Exception)
        {
        }

        return devices;
    }

    private ICaptureDevice ResolveDevice(string deviceName)
    {
        for (int attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                CaptureDeviceList.Instance.Refresh();
            }
            catch (Exception)
            {
            }

            var match = CaptureDeviceList.Instance.FirstOrDefault(d => d.Name == deviceName);
            if (match is not null)
            {
                return match;
            }

            Thread.Sleep(200);
        }

        throw new InvalidOperationException($"No capture device found with name '{deviceName}'.");
    }

    private void RefreshLocalAddresses(ICaptureDevice device)
    {
        _localAddresses.Clear();

        try
        {
            if (device is LibPcapLiveDevice liveDevice)
            {
                foreach (var address in liveDevice.Addresses)
                {
                    var ip = address.Addr?.ipAddress?.ToString();
                    if (!string.IsNullOrEmpty(ip))
                    {
                        _localAddresses.Add(ip);
                    }
                }
            }
        }
        catch (Exception)
        {
        }

        if (_localAddresses.Count == 0)
        {
            foreach (var info in SnapshotDevices())
            {
                if (!string.IsNullOrEmpty(info.IpAddress))
                {
                    _localAddresses.Add(info.IpAddress);
                }
            }
        }
    }

    private bool IsLocalAddress(string ip) => _localAddresses.Contains(ip);

    private bool IsInboundPacket(string sourceIp, string destinationIp) =>
        _localAddresses.Count == 0 || (IsLocalAddress(destinationIp) && !IsLocalAddress(sourceIp));

    public void Start(string deviceName)
    {
        _device = ResolveDevice(deviceName);

        RefreshLocalAddresses(_device);

        _device.OnPacketArrival += OnPacketArrival;
        _device.Open(DeviceModes.Promiscuous, 1000);
        _device.StartCapture();

        _expiryTimer.Change(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        _liveSummaryTimer.Change(TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
    }

    public void Stop()
    {
        _expiryTimer.Change(Timeout.Infinite, Timeout.Infinite);
        _liveSummaryTimer.Change(Timeout.Infinite, Timeout.Infinite);

        if (_device is not null)
        {
            try
            {
                _device.StopCapture();
            }
            catch (Exception)
            {
            }

            _device.OnPacketArrival -= OnPacketArrival;

            try
            {
                _device.Close();
            }
            catch (Exception)
            {
            }

            _device = null;
        }

        _flows.Clear();
    }

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            ProcessPacket(e);
        }
        catch (Exception)
        {
        }
    }

    private void ProcessPacket(PacketCapture e)
    {
        RawCapture rawPacket = e.GetPacket();
        Packet parsed = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        ProcessPacket(parsed, DateTime.Now);
    }

    internal void ProcessPacket(Packet parsed, DateTime now)
    {
        IPPacket? ipPacket = parsed.Extract<IPPacket>();
        if (ipPacket is null) return; 

        TcpPacket? tcpPacket = parsed.Extract<TcpPacket>();
        UdpPacket? udpPacket = parsed.Extract<UdpPacket>();

        string srcIp = ipPacket.SourceAddress.ToString();
        string dstIp = ipPacket.DestinationAddress.ToString();
        ushort srcPort = tcpPacket?.SourcePort ?? udpPacket?.SourcePort ?? 0;
        ushort dstPort = tcpPacket?.DestinationPort ?? udpPacket?.DestinationPort ?? 0;
        byte protocol = (byte)ipPacket.Protocol;
        int packetSize = ipPacket.TotalLength;
        UpdateFastPathCounters(packetSize, protocol);

        Packet? transportPacket = (Packet?)tcpPacket ?? udpPacket;
        int flowPacketSize = transportPacket is null
            ? packetSize
            : transportPacket.PayloadDataSegment?.Length ?? transportPacket.PayloadPacket?.TotalPacketLength ?? 0;

        if (HeuristicEnabled)
        {
            var observation = new PacketObservation(
                SourceIp: srcIp,
                DestinationIp: dstIp,
                DestinationPort: dstPort,
                Protocol: protocol,
                IsSyn: tcpPacket?.Synchronize ?? false,
                IsRst: tcpPacket?.Reset ?? false,
                PacketSize: packetSize,
                Timestamp: now,
                IsInbound: IsInboundPacket(srcIp, dstIp),
                IsFin: tcpPacket?.Finished ?? false,
                IsAck: tcpPacket?.Acknowledgment ?? false);
            _behavior.Observe(observation);

            var immediate = _behavior.EvaluateFast(observation);
            if (immediate is not null)
            {
                EmitImmediateAlert(srcIp, srcPort, dstIp, dstPort, protocol, tcpPacket, immediate, now);
            }
        }

        var key = Internal.FlowKey.Create(srcIp, srcPort, dstIp, dstPort, protocol);

        if (_flows.Count >= MaxFlowCount && !_flows.ContainsKey(key))
        {
            return;
        }

        bool srcIsLocal = IsLocalAddress(srcIp);
        bool dstIsLocal = IsLocalAddress(dstIp);
        bool swap = srcIsLocal && !dstIsLocal;

        string flowSourceIp = swap ? dstIp : srcIp;
        ushort flowSourcePort = swap ? dstPort : srcPort;
        string flowDestinationIp = swap ? srcIp : dstIp;
        ushort flowDestinationPort = swap ? srcPort : dstPort;

        bool isInbound = IsInboundPacket(srcIp, dstIp);

        var flow = _flows.GetOrAdd(key, _ => new Internal.FlowRecord
        {
            StartTime = now,
            LastSeenTime = now,
            Protocol = protocol,
            DestinationPort = flowDestinationPort,
            SourceIp = flowSourceIp,
            SourcePort = flowSourcePort,
            DestinationIp = flowDestinationIp,
            IsInbound = isInbound
        });

        bool isForward = srcIp == flow.SourceIp && srcPort == flow.SourcePort;

        lock (flow) 
        {
            flow.PacketSizeStats.Add(flowPacketSize);

            if (isForward)
            {
                flow.FwdPackets++;
                flow.FwdBytes += flowPacketSize;
                if (flow.LastFwdPacketTime is { } lastFwd)
                    flow.FwdIatStats.Add((now - lastFwd).TotalMilliseconds);
                flow.LastFwdPacketTime = now;
            }
            else
            {
                flow.BwdPackets++;
                flow.BwdBytes += flowPacketSize;
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

    private void SafeExpireIdleFlows()
    {
        try
        {
            ExpireIdleFlows(DateTime.Now);
        }
        catch (Exception)
        {
        }
    }

    private void SafeEmitLiveSummary()
    {
        try
        {
            EmitLiveSummary();
        }
        catch (Exception)
        {
        }
    }

    internal void ExpireIdleFlows(DateTime now)
    {
        var timeout = TimeSpan.FromSeconds(_flowIdleTimeoutSeconds);
        var deadline = DateTime.UtcNow + ExpiryTimeBudget;

        _behavior.Prune(now);

        foreach (var (key, flow) in _flows)
        {
            if (DateTime.UtcNow >= deadline) break;

            bool isIdle;
            lock (flow) { isIdle = now - flow.LastSeenTime > timeout; }
            if (!isIdle) continue;

            if (!_flows.TryRemove(key, out _)) continue; 

            PreFilterResult verdict;
            if (HeuristicEnabled)
            {
                verdict = _behavior.Evaluate(flow.SourceIp, now) ?? _preFilter.Classify(ToStatistics(flow));
                if (!verdict.IsKnownAttack && !verdict.IsSuspicious) continue;
            }
            else
            {
                verdict = PreFilterResult.Suspicious("Heuristic detection disabled; forwarded to the AI engine.");
            }

            var featureVector = Internal.FeatureExporter.Export(
                flow, key,
                sourceIp: flow.SourceIp, sourcePort: flow.SourcePort,
                destinationIp: flow.DestinationIp, destinationPort: (ushort)flow.DestinationPort,
                protocol: key.Protocol);

            var completed = new FlowFeatureVector
            {
                Features = featureVector.Features,
                SourceIp = featureVector.SourceIp,
                SourcePort = featureVector.SourcePort,
                DestinationIp = featureVector.DestinationIp,
                DestinationPort = featureVector.DestinationPort,
                Protocol = featureVector.Protocol,
                FlowStartTime = featureVector.FlowStartTime,
                FlowEndTime = featureVector.FlowEndTime,
                SynCount = featureVector.SynCount,
                AckCount = featureVector.AckCount,
                FinCount = featureVector.FinCount,
                RstCount = featureVector.RstCount,
                PshCount = featureVector.PshCount,
                PreFilterVerdict = verdict,
                IsInbound = flow.IsInbound
            };

            ThreadPool.QueueUserWorkItem(_ => RaiseFlowCompleted(completed));
        }
    }

    private static FlowStatistics ToStatistics(Internal.FlowRecord flow) => new()
    {
        Protocol = flow.Protocol,
        DestinationPort = flow.DestinationPort,
        FwdPackets = flow.FwdPackets,
        BwdPackets = flow.BwdPackets,
        FwdBytes = flow.FwdBytes,
        BwdBytes = flow.BwdBytes,
        SynCount = flow.SynCount,
        AckCount = flow.AckCount,
        FinCount = flow.FinCount,
        RstCount = flow.RstCount,
        PshCount = flow.PshCount,
        DurationSeconds = flow.DurationSeconds,
        PacketSizeMean = flow.PacketSizeStats.Mean,
        PacketSizeStdDev = flow.PacketSizeStats.StdDev
    };

    private void RaiseFlowCompleted(FlowFeatureVector flow)
    {
        try
        {
            OnFlowCompleted?.Invoke(this, flow);
        }
        catch (Exception)
        {
        }
    }

    private void EmitImmediateAlert(
        string sourceIp,
        ushort sourcePort,
        string destinationIp,
        ushort destinationPort,
        byte protocol,
        TcpPacket? tcpPacket,
        PreFilterResult verdict,
        DateTime now)
    {
        var completed = new FlowFeatureVector
        {
            Features = new float[Internal.FeatureExporter.FeatureNames.Length],
            SourceIp = sourceIp,
            SourcePort = sourcePort,
            DestinationIp = destinationIp,
            DestinationPort = destinationPort,
            Protocol = protocol,
            FlowStartTime = now,
            FlowEndTime = now,
            SynCount = tcpPacket?.Synchronize == true ? 1 : 0,
            AckCount = tcpPacket?.Acknowledgment == true ? 1 : 0,
            FinCount = tcpPacket?.Finished == true ? 1 : 0,
            RstCount = tcpPacket?.Reset == true ? 1 : 0,
            PshCount = tcpPacket?.Push == true ? 1 : 0,
            PreFilterVerdict = verdict,
            IsInbound = IsInboundPacket(sourceIp, destinationIp)
        };

        ThreadPool.QueueUserWorkItem(_ => RaiseFlowCompleted(completed));
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
            PacketsPerSecond = packets / elapsedSeconds,
            BytesPerSecond = bytes / elapsedSeconds,
            Bytes = bytes,
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

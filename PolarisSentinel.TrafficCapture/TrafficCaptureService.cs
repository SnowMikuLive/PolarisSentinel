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

    private readonly int _flowIdleTimeoutSeconds;
    private readonly System.Threading.Timer _expiryTimer;
    private readonly System.Threading.Timer _liveSummaryTimer;
    public static string[] FeatureNames => Internal.FeatureExporter.FeatureNames;
    private ICaptureDevice? _device;

    // Guards the device snapshot cache so concurrent API calls do not race.
    private readonly object _deviceLock = new();

    // Last known-good device list; never replaced by a smaller (transiently incomplete) one.
    private List<NetworkInterfaceInfo> _cachedDevices = new();

    // Fast-path counters, reset every time OnLiveTrafficSummary fires.
    private long _packetsSinceLastTick;
    private long _bytesSinceLastTick;
    private long _tcpSinceLastTick;
    private long _udpSinceLastTick;
    private long _icmpSinceLastTick;
    private DateTime _lastTickTime = DateTime.Now;

    private const int MaxFlowCount = 100000;

    // Expiry runs on a timer thread; cap each cycle by wall-clock time so a flood of
    // tens of thousands of idle flows cannot stall the timer indefinitely. The
    // remainder is picked up on the next tick.
    private static readonly TimeSpan ExpiryTimeBudget = TimeSpan.FromMilliseconds(200);

    // Behavioural detection window: a source is judged on the last N seconds of activity.
    private static readonly TimeSpan BehaviorWindow = TimeSpan.FromSeconds(10);

    public event EventHandler<FlowFeatureVector>? OnFlowCompleted;
    public event EventHandler<LiveTrafficSummary>? OnLiveTrafficSummary;


    // From PolicySettings.FlowIdleTimeoutSeconds. A flow with no new packets for this many seconds is considered finished and exported.

    public TrafficCaptureService(
        int flowIdleTimeoutSeconds,
        int preFilterMinPackets,
        int liveSummaryIntervalSeconds = 5)
    {
        _flowIdleTimeoutSeconds = flowIdleTimeoutSeconds;
        _preFilter = new PreFilter(preFilterMinPackets);
        _behavior = new SourceBehaviorTracker(BehaviorWindow);

        // Both timers are created suspended (Timeout.Infinite due time) and
        // only actually start ticking once Start(deviceName) is called.
        // The callbacks swallow exceptions: an unhandled throw on a timer thread
        // would terminate the whole process.
        _expiryTimer = new System.Threading.Timer(_ => SafeExpireIdleFlows(), null, Timeout.Infinite, Timeout.Infinite);
        _liveSummaryTimer = new System.Threading.Timer(_ => SafeEmitLiveSummary(), null, Timeout.Infinite, Timeout.Infinite);
    }

    public IEnumerable<NetworkInterfaceInfo> GetAvailableDevices()
    {
        // Enumerating the live SharpPcap cache is unstable: Refresh() replaces the
        // list and can transiently return an incomplete set (adapters disappear),
        // which made the UI's network-interface selector lose entries after a flood.
        // Snapshot once, keep the last good list, and only replace it when the new
        // enumeration is at least as complete.
        return SnapshotDevices();
    }

    // Builds a stable, cached snapshot of the capture devices.
    private List<NetworkInterfaceInfo> SnapshotDevices()
    {
        lock (_deviceLock)
        {
            var fresh = EnumerateDevices();
            if (fresh.Count >= _cachedDevices.Count)
            {
                _cachedDevices = fresh;
            }

            // Never hand back an empty list once a good one has been seen.
            return _cachedDevices.Count > 0 ? new List<NetworkInterfaceInfo>(_cachedDevices) : fresh;
        }
    }

    // Enumerates the current SharpPcap device list defensively.
    private static List<NetworkInterfaceInfo> EnumerateDevices()
    {
        try
        {
            CaptureDeviceList.Instance.Refresh();
        }
        catch (Exception)
        {
            // A failed refresh is non-fatal: fall back to whatever is cached.
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
                    // Skip a device whose addresses cannot be read rather than failing the
                    // whole enumeration; still surface it by name so it stays selectable.
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
            // The whole list threw mid-enumeration; return what we collected so far.
        }

        return devices;
    }

    // Resolves a device by name, refreshing and retrying a few times because the
    // pcap cache can briefly omit a device right after a flood.
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

    public void Start(string deviceName)
    {
        // The device list is cached by SharpPcap. After a flood the adapter state can
        // change, so resolve with a retry loop before giving up.
        _device = ResolveDevice(deviceName);

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
            // A driver in a bad state can throw here; the handle must still be released
            // so the next Start() is not blocked by a half-closed device.
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

        // Drop accumulated flow state so a restart begins clean.
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
            // A malformed or unsupported packet must never kill the capture thread.
        }
    }

    private void ProcessPacket(PacketCapture e)
    {
        RawCapture rawPacket = e.GetPacket();
        Packet parsed = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        ProcessPacket(parsed, DateTime.Now);
    }

    // 分开解析和处理，测试可以直接传入样本包。
    // Separate parsing from processing so tests can pass sample packets.
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

        // Behavioural detection sees every packet, independent of flow aggregation, so a
        // scan or brute-force run that spreads across many short flows is still caught.
        _behavior.Observe(new PacketObservation(
            SourceIp: srcIp,
            DestinationPort: dstPort,
            Protocol: protocol,
            IsSyn: tcpPacket?.Synchronize ?? false,
            IsRst: tcpPacket?.Reset ?? false,
            PacketSize: packetSize,
            Timestamp: now));

        var key = Internal.FlowKey.Create(srcIp, srcPort, dstIp, dstPort, protocol);

        // A flood (or a spoofed-source scan) can create flows faster than they expire.
        // Cap the table so memory stays bounded; the expiry timer drains it afterwards.
        if (_flows.Count >= MaxFlowCount && !_flows.ContainsKey(key))
        {
            return;
        }

        var flow = _flows.GetOrAdd(key, _ => new Internal.FlowRecord
        {
            StartTime = now,
            LastSeenTime = now,
            Protocol = protocol,
            DestinationPort = dstPort,
            SourceIp = srcIp,
            SourcePort = srcPort,
            DestinationIp = dstIp
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

    private void SafeExpireIdleFlows()
    {
        try
        {
            ExpireIdleFlows();
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

    private void ExpireIdleFlows()
    {
        ExpireIdleFlows(DateTime.Now);
    }

    internal void ExpireIdleFlows(DateTime now)
    {
        var timeout = TimeSpan.FromSeconds(_flowIdleTimeoutSeconds);
        var deadline = DateTime.UtcNow + ExpiryTimeBudget;

        // Drop behavioural windows that have gone quiet so the tracker does not grow.
        _behavior.Prune(now);

        // A flood can leave tens of thousands of idle flows at once. Processing them
        // all in one cycle would block this timer thread, so each cycle runs until a
        // wall-clock budget is spent; the remainder is picked up on the next tick.
        foreach (var (key, flow) in _flows)
        {
            if (DateTime.UtcNow >= deadline) break;

            bool isIdle;
            lock (flow) { isIdle = now - flow.LastSeenTime > timeout; }
            if (!isIdle) continue;

            if (!_flows.TryRemove(key, out _)) continue; // another thread already removed it

            // Behavioural detection first: a scan or brute-force run is invisible to a
            // single flow but obvious across the source's recent activity.
            var verdict = _behavior.Evaluate(flow.SourceIp, now);

            // Otherwise fall back to the per-flow pre-filter: attack verdicts are emitted,
            // benign flows are dropped, and only unclassified flows reach AI inference.
            verdict ??= _preFilter.Classify(ToStatistics(flow));
            if (!verdict.IsKnownAttack && !verdict.IsSuspicious) continue;

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
                TotalPackets = featureVector.TotalPackets,
                TotalBytes = featureVector.TotalBytes,
                SynCount = featureVector.SynCount,
                AckCount = featureVector.AckCount,
                FinCount = featureVector.FinCount,
                RstCount = featureVector.RstCount,
                PshCount = featureVector.PshCount,
                PreFilterVerdict = verdict
            };

            // Hand off to the thread pool so a slow subscriber (DB + inference + SignalR)
            // cannot stall the expiry timer.
            ThreadPool.QueueUserWorkItem(_ => RaiseFlowCompleted(completed));
        }
    }

    // Projects the capture adapter's mutable flow record onto the immutable domain
    // statistics the pre-filter classifies, so the detection rules stay capture-agnostic.
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
            // A subscriber fault must not take down the process.
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

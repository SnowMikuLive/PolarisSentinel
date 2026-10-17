using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using Microsoft.Extensions.Logging;
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
    private readonly ILogger<TrafficCaptureService>? _logger;

    private bool HeuristicEnabled => _detection?.HeuristicEnabled ?? true;

    private readonly int _flowIdleTimeoutSeconds;
    private readonly int _liveSummaryIntervalSeconds;
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
        DetectionRuntimeState? detection = null,
        ILogger<TrafficCaptureService>? logger = null)
    {
        _flowIdleTimeoutSeconds = flowIdleTimeoutSeconds;
        _liveSummaryIntervalSeconds = liveSummaryIntervalSeconds > 0 ? liveSummaryIntervalSeconds : 5;
        _preFilter = new PreFilter(thresholds);
        _behavior = new SourceBehaviorTracker(BehaviorWindow, thresholds, BehaviorCooldown);
        _detection = detection;
        _logger = logger;

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
            var fresh = EnumerateDevices(_logger);

            if (fresh.Count > 0)
            {
                _cachedDevices = fresh;
            }

            var result = _cachedDevices.Count > 0 ? new List<NetworkInterfaceInfo>(_cachedDevices) : fresh;
            LogDevices(result);
            return result;
        }
    }

    private void LogDevices(List<NetworkInterfaceInfo> devices)
    {
        if (_logger is null)
        {
            return;
        }

        if (devices.Count == 0)
        {
            _logger.LogWarning("No capture devices were reported by the packet capture driver.");
            return;
        }

        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation(
                "Capture devices: {Devices}",
                string.Join("; ", devices.Select(d =>
                    $"{d.DisplayName} ip={d.IpAddress ?? "-"} mac={d.MacAddress ?? "-"} loopback={d.IsLoopback} active={d.IsDefaultRoute} [{d.DeviceName}]")));
        }
    }

    private static List<NetworkInterfaceInfo> EnumerateDevices(ILogger? logger)
    {
        var devices = new List<NetworkInterfaceInfo>();

        try
        {
            foreach (var device in RefreshCaptureDevices(logger))
            {
                devices.Add(DescribeDevice(device, logger));
            }
        }
        catch (Exception ex)
        {
            logger?.LogWarning(ex, "Capture device enumeration failed");
        }

        return devices
            .OrderBy(d => d.IsLoopback)
            .ThenBy(d => string.IsNullOrEmpty(d.IpAddress))
            .ThenBy(d => d.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static NetworkInterfaceInfo DescribeDevice(ICaptureDevice device, ILogger? logger)
    {
        var name = device.Name ?? string.Empty;
        var description = string.IsNullOrWhiteSpace(device.Description) ? name : device.Description;

        string? ip = null;
        string? mac = null;

        if (device is LibPcapLiveDevice liveDevice)
        {
            try
            {
                ip = SelectPreferredAddress(liveDevice.Addresses.Select(a => a.Addr?.ipAddress));
            }
            catch (Exception ex)
            {
                if (logger?.IsEnabled(LogLevel.Debug) == true)
                {
                    logger.LogDebug(ex, "Could not read the addresses of {Device}", name);
                }
            }

            try
            {
                mac = liveDevice.MacAddress?.ToString();
            }
            catch (Exception ex)
            {
                if (logger?.IsEnabled(LogLevel.Debug) == true)
                {
                    logger.LogDebug(ex, "Could not read the MAC address of {Device}", name);
                }
            }
        }

        var isLoopback = name.Contains("loopback", StringComparison.OrdinalIgnoreCase)
            || description.Contains("loopback", StringComparison.OrdinalIgnoreCase);

        return new NetworkInterfaceInfo
        {
            DeviceName = name,
            DisplayName = description,
            IpAddress = ip,
            IsLoopback = isLoopback,
            IsDefaultRoute = IsDefaultRouteDevice(ip),
            MacAddress = mac
        };
    }

    private static bool IsDefaultRouteDevice(string? address)
    {
        if (string.IsNullOrEmpty(address))
        {
            return false;
        }

        try
        {
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (adapter.OperationalStatus != OperationalStatus.Up)
                {
                    continue;
                }

                var properties = adapter.GetIPProperties();

                bool hasGateway = properties.GatewayAddresses.Any(g =>
                    g.Address is not null &&
                    g.Address.AddressFamily == AddressFamily.InterNetwork &&
                    !g.Address.Equals(IPAddress.Any));

                if (!hasGateway)
                {
                    continue;
                }

                if (properties.UnicastAddresses.Any(u =>
                        string.Equals(u.Address?.ToString(), address, StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(ex);
        }

        return false;
    }

    private static string? SelectPreferredAddress(IEnumerable<IPAddress?> addresses)
    {
        var usable = addresses.Where(a => a is not null).Select(a => a!).ToList();
        if (usable.Count == 0)
        {
            return null;
        }

        return usable
            .OrderBy(AddressRank)
            .Select(a => a.ToString())
            .First();

        static int AddressRank(IPAddress address)
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                if (IPAddress.IsLoopback(address)) return 3;
                if (IsApipaV4(address)) return 2;
                return 0;
            }

            if (IPAddress.IsLoopback(address)) return 4;
            if (address.IsIPv6LinkLocal) return 3;
            return 1;
        }

        static bool IsApipaV4(IPAddress address)
        {
            var bytes = address.GetAddressBytes();
            return bytes.Length == 4 && bytes[0] == 169 && bytes[1] == 254;
        }
    }

    private static List<ILiveDevice> RefreshCaptureDevices(ILogger? logger = null)
    {
        try
        {
            CaptureDeviceList.Instance.Refresh();
        }
        catch (Exception ex)
        {
            logger?.LogWarning(ex, "Refreshing the capture device list failed");
        }

        return CaptureDeviceList.Instance.ToList();
    }

    private static ICaptureDevice ResolveDevice(string deviceName)
    {
        for (int attempt = 0; attempt < 3; attempt++)
        {
            var devices = RefreshCaptureDevices();

            var match = devices.FirstOrDefault(d => string.Equals(d.Name, deviceName, StringComparison.OrdinalIgnoreCase))
                ?? devices.FirstOrDefault(d => string.Equals(d.Description, deviceName, StringComparison.OrdinalIgnoreCase));

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
        TryAddDeviceAddresses(device);

        if (_localAddresses.Count == 0)
        {
            AddSnapshotAddresses(device);
        }
    }

    private void TryAddDeviceAddresses(ICaptureDevice device)
    {
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
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(ex);
        }
    }

    private void AddSnapshotAddresses(ICaptureDevice device)
    {
        var snapshot = SnapshotDevices();
        var selectedIp = snapshot
            .FirstOrDefault(d => string.Equals(d.DeviceName, device.Name, StringComparison.OrdinalIgnoreCase))
            ?.IpAddress;

        if (!string.IsNullOrEmpty(selectedIp))
        {
            _localAddresses.Add(selectedIp);
            return;
        }

        foreach (var info in snapshot)
        {
            if (!string.IsNullOrEmpty(info.IpAddress))
            {
                _localAddresses.Add(info.IpAddress);
            }
        }
    }

    private bool IsLocalAddress(string ip) => _localAddresses.Contains(ip);

    private bool IsInboundPacket(string sourceIp, string destinationIp) =>
        _localAddresses.Count == 0 || (IsLocalAddress(destinationIp) && !IsLocalAddress(sourceIp));

    public void Start(string deviceName)
    {
        var device = ResolveDevice(deviceName);
        _device = device;

        try
        {
            RefreshLocalAddresses(device);
            device.OnPacketArrival += OnPacketArrival;
            device.Open(DeviceModes.Promiscuous, 1000);
            device.StartCapture();
        }
        catch
        {
            try { device.OnPacketArrival -= OnPacketArrival; }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
            try { device.Close(); }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
            _device = null;
            throw;
        }

        _expiryTimer.Change(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        _liveSummaryTimer.Change(
            TimeSpan.FromSeconds(_liveSummaryIntervalSeconds),
            TimeSpan.FromSeconds(_liveSummaryIntervalSeconds));
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
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex);
            }

            _device.OnPacketArrival -= OnPacketArrival;

            try
            {
                _device.Close();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex);
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
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(ex);
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

        PreFilterResult? immediateVerdict = null;
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

            immediateVerdict = _behavior.EvaluateFast(observation);
        }

        var key = Internal.FlowKey.Create(srcIp, srcPort, dstIp, dstPort, protocol);

        Internal.FlowRecord? flow = null;
        if (_flows.Count < MaxFlowCount || _flows.ContainsKey(key))
        {
            bool srcIsLocal = IsLocalAddress(srcIp);
            bool dstIsLocal = IsLocalAddress(dstIp);
            bool swap = srcIsLocal && !dstIsLocal;

            string flowSourceIp = swap ? dstIp : srcIp;
            ushort flowSourcePort = swap ? dstPort : srcPort;
            string flowDestinationIp = swap ? srcIp : dstIp;
            ushort flowDestinationPort = swap ? srcPort : dstPort;

            bool isInbound = IsInboundPacket(srcIp, dstIp);

            flow = _flows.GetOrAdd(key, _ => new Internal.FlowRecord
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

        if (immediateVerdict is not null)
        {
            EmitImmediateAlert(flow, key, srcIp, srcPort, dstIp, dstPort, protocol, tcpPacket, immediateVerdict, now);
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
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(ex);
        }
    }

    private void SafeEmitLiveSummary()
    {
        try
        {
            EmitLiveSummary();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(ex);
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
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(ex);
        }
    }

    private void EmitImmediateAlert(
        Internal.FlowRecord? flow,
        Internal.FlowKey key,
        string sourceIp,
        ushort sourcePort,
        string destinationIp,
        ushort destinationPort,
        byte protocol,
        TcpPacket? tcpPacket,
        PreFilterResult verdict,
        DateTime now)
    {
        FlowFeatureVector completed;

        if (flow is not null)
        {

            lock (flow)
            {
                completed = Internal.FeatureExporter.Export(
                    flow, key,
                    sourceIp: flow.SourceIp, sourcePort: flow.SourcePort,
                    destinationIp: flow.DestinationIp, destinationPort: (ushort)flow.DestinationPort,
                    protocol: flow.Protocol,
                    preFilterVerdict: verdict,
                    isInbound: flow.IsInbound);
            }
        }
        else
        {

            completed = new FlowFeatureVector
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
        }

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

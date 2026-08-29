using System;
using System.Text;
using PolarisSentinel.TrafficCapture;
using PolarisSentinel.TrafficCapture.Internal;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.ConsoleTest;

internal class Program
{
    private static readonly CancellationTokenSource _cts = new();
    private static TrafficCaptureService? _captureService;
    private static int _flowCounter;
    private static readonly object _consoleLock = new();
    private static readonly string[] _featureNames = TrafficCaptureService.FeatureNames;

    private static async Task Main(string[] args)
    {
        Console.WriteLine("Polaris Sentinel - Traffic Capture Test");
        Console.WriteLine();

        Console.CancelKeyPress += (sender, e) =>
        {
            e.Cancel = true;
            _cts.Cancel();
            Console.WriteLine("\nShutting down...");
        };

        try
        {
            await RunCaptureAsync();
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("Capture stopped.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }
        finally
        {
            _captureService?.Dispose();
        }
    }

    private static async Task RunCaptureAsync()
    {
        _captureService = new TrafficCaptureService(
            flowIdleTimeoutSeconds: 30,
            preFilterMinPackets: 3,
            liveSummaryIntervalSeconds: 5
        );

        _captureService.OnFlowCompleted += OnFlowCompleted;
        _captureService.OnLiveTrafficSummary += OnLiveTrafficSummary;

        var devices = _captureService.GetAvailableDevices().ToList();

        if (devices.Count == 0)
        {
            Console.WriteLine("No network interfaces found!");
            return;
        }

        Console.WriteLine("Available network interfaces:");
        for (int i = 0; i < devices.Count; i++)
        {
            var dev = devices[i];
            Console.WriteLine($"[{i}] {dev.DisplayName} ({dev.IpAddress ?? "N/A"})");
        }

        Console.Write("Select device number: ");
        if (!int.TryParse(Console.ReadLine(), out int index) || index < 0 || index >= devices.Count)
        {
            Console.WriteLine("Invalid selection.");
            return;
        }

        var selectedDevice = devices[index];
        Console.WriteLine($"Starting capture on: {selectedDevice.DisplayName}");
        Console.WriteLine("Press Ctrl+C to stop");
        Console.WriteLine();

        _captureService.Start(selectedDevice.DeviceName);

        try
        {
            await Task.Delay(Timeout.Infinite, _cts.Token);
        }
        catch (TaskCanceledException) { }

        _captureService.Stop();
        Console.WriteLine("Capture stopped.");
        await Task.Delay(500);
    }

    private static void OnFlowCompleted(object? sender, FlowFeatureVector flow)
    {
        lock (_consoleLock)
        {
            _flowCounter++;
            Console.WriteLine(new string('-', 70));

            // ===== REAL-TIME TRAFFIC =====
            Console.WriteLine($"[FLOW #{_flowCounter}] REAL-TIME TRAFFIC");
            Console.WriteLine($"  Source: {flow.SourceIp}:{flow.SourcePort}");
            Console.WriteLine($"  Dest:   {flow.DestinationIp}:{flow.DestinationPort}");
            Console.WriteLine($"  Protocol: {ProtocolToString(flow.Protocol)}");
            Console.WriteLine($"  Duration: {(flow.FlowEndTime - flow.FlowStartTime).TotalSeconds:F2}s");
            Console.WriteLine($"  Packets: {flow.TotalPackets} | Bytes: {FormatBytes(flow.TotalBytes)}");
            Console.WriteLine();

            // ===== AI FEATURE VECTOR =====
            Console.WriteLine($"[FLOW #{_flowCounter}] AI FEATURE VECTOR");
            for (int i = 0; i < flow.Features.Length && i < _featureNames.Length; i++)
            {
                Console.WriteLine($"  {_featureNames[i],-20}: {FormatValue(_featureNames[i], flow.Features[i])}");
            }
            Console.WriteLine();

            // JSON format for AI engine
            Console.WriteLine($"[FLOW #{_flowCounter}] JSON (for AI Engine)");
            Console.WriteLine(FormatAsJson(flow));
            Console.WriteLine(new string('-', 70));
        }
    }

    private static void OnLiveTrafficSummary(object? sender, LiveTrafficSummary summary)
    {
        lock (_consoleLock)
        {
            Console.WriteLine($"[LIVE] {summary.Timestamp:HH:mm:ss} | " +
                              $"PPS: {summary.PacketsPerSecond:F1} | " +
                              $"BPS: {FormatBytes((long)summary.BytesPerSecond)}/s | " +
                              $"Active Flows: {summary.ActiveFlowCount} | " +
                              $"TCP: {summary.TcpShare:P0} UDP: {summary.UdpShare:P0} ICMP: {summary.IcmpShare:P0}");
        }
    }

    private static string ProtocolToString(byte protocol)
    {
        return protocol switch
        {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            _ => $"Unknown({protocol})"
        };
    }

    private static string FormatValue(string name, float value)
    {
        if (name.Contains("count") || name.Contains("packets") || name == "destination_port")
            return ((long)value).ToString();
        if (name.Contains("duration"))
            return $"{value:F3}s";
        if (name.Contains("ratio"))
            return $"{value:F4}";
        return $"{value:F2}";
    }

    private static string FormatAsJson(FlowFeatureVector flow)
    {
        var sb = new StringBuilder();
        sb.Append("{");
        sb.Append($"\"source\":\"{flow.SourceIp}:{flow.SourcePort}\",");
        sb.Append($"\"dest\":\"{flow.DestinationIp}:{flow.DestinationPort}\",");
        sb.Append($"\"protocol\":{flow.Protocol},");
        sb.Append($"\"features\":[{string.Join(",", flow.Features.Select(f => f.ToString("F6")))}]");
        sb.Append("}");
        return sb.ToString();
    }

    private static string FormatBytes(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB" };
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }
        return $"{len:0.#}{sizes[order]}";
    }
}
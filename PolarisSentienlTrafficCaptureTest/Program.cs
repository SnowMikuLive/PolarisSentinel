using System;
using System.Text;
using System.Linq;
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
        Console.WriteLine($"Feature Count: {_featureNames.Length}");
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

            // ===== FLOW HEADER =====
            Console.WriteLine(new string('=', 80));
            Console.WriteLine($"[FLOW #{_flowCounter}]");
            Console.WriteLine(new string('-', 80));

            // ===== BASIC FLOW INFO =====
            Console.WriteLine("  BASIC FLOW INFO");
            Console.WriteLine($"    Source:      {flow.SourceIp}:{flow.SourcePort}");
            Console.WriteLine($"    Destination: {flow.DestinationIp}:{flow.DestinationPort}");
            Console.WriteLine($"    Protocol:    {ProtocolToString(flow.Protocol)}");
            Console.WriteLine($"    Start Time:  {flow.FlowStartTime:HH:mm:ss.fff}");
            Console.WriteLine($"    End Time:    {flow.FlowEndTime:HH:mm:ss.fff}");
            Console.WriteLine($"    Duration:    {(flow.FlowEndTime - flow.FlowStartTime).TotalSeconds:F3}s");
            Console.WriteLine($"    Total Packets: {flow.TotalPackets}");
            Console.WriteLine($"    Total Bytes:   {FormatBytes(flow.TotalBytes)}");
            Console.WriteLine();

            // ===== AI FEATURE VECTOR (Grouped by category) =====
            Console.WriteLine("  AI FEATURE VECTOR (20 features)");
            Console.WriteLine("  " + new string('-', 76));

            // Duration & Packets
            Console.WriteLine("    [Duration & Packets]");
            PrintFeature("flow_duration_seconds", flow.Features[0]);
            PrintFeature("total_fwd_packets", flow.Features[1]);
            PrintFeature("total_bwd_packets", flow.Features[2]);
            PrintFeature("total_fwd_bytes", flow.Features[3]);
            PrintFeature("total_bwd_bytes", flow.Features[4]);
            Console.WriteLine();

            // Packet Length Statistics
            Console.WriteLine("    [Packet Length Statistics]");
            PrintFeature("pkt_len_min", flow.Features[5]);
            PrintFeature("pkt_len_max", flow.Features[6]);
            PrintFeature("pkt_len_mean", flow.Features[7]);
            PrintFeature("pkt_len_std", flow.Features[8]);
            Console.WriteLine();

            // Forward IAT Statistics
            Console.WriteLine("    [Forward IAT Statistics]");
            PrintFeature("fwd_iat_mean_ms", flow.Features[9]);
            PrintFeature("fwd_iat_std_ms", flow.Features[10]);
            PrintFeature("fwd_iat_max_ms", flow.Features[11]);
            PrintFeature("fwd_iat_min_ms", flow.Features[12]);
            Console.WriteLine();

            // Backward IAT Statistics
            Console.WriteLine("    [Backward IAT Statistics]");
            PrintFeature("bwd_iat_mean_ms", flow.Features[13]);
            PrintFeature("bwd_iat_std_ms", flow.Features[14]);
            PrintFeature("bwd_iat_max_ms", flow.Features[15]);
            PrintFeature("bwd_iat_min_ms", flow.Features[16]);
            Console.WriteLine();

            // Rate & Ratio
            Console.WriteLine("    [Rate & Ratio]");
            PrintFeature("flow_bytes_per_ms", flow.Features[17]);
            PrintFeature("flow_pkts_per_ms", flow.Features[18]);
            PrintFeature("down_up_ratio", flow.Features[19]);
            Console.WriteLine();

            // ===== JSON FORMAT (Compact) =====
            Console.WriteLine("  JSON (for AI Engine)");
            Console.WriteLine($"    {FormatAsJson(flow)}");
            Console.WriteLine(new string('=', 80));
        }
    }

    private static void PrintFeature(string name, float value)
    {
        string displayValue = name switch
        {
            "flow_duration_seconds" => $"{value:F3}s",
            "total_fwd_packets" or "total_bwd_packets" => ((long)value).ToString(),
            "total_fwd_bytes" or "total_bwd_bytes" => FormatBytes((long)value),
            "pkt_len_min" or "pkt_len_max" or "pkt_len_mean" or "pkt_len_std" => $"{value:F2} bytes",
            "fwd_iat_mean_ms" or "fwd_iat_std_ms" or "fwd_iat_max_ms" or "fwd_iat_min_ms" or
            "bwd_iat_mean_ms" or "bwd_iat_std_ms" or "bwd_iat_max_ms" or "bwd_iat_min_ms" => $"{value:F3} ms",
            "flow_bytes_per_ms" => $"{value:F3} bytes/ms",
            "flow_pkts_per_ms" => $"{value:F3} packets/ms",
            "down_up_ratio" => $"{value:F4}",
            _ => $"{value:F2}"
        };

        Console.WriteLine($"      {name,-20}: {displayValue}");
    }

    private static void OnLiveTrafficSummary(object? sender, LiveTrafficSummary summary)
    {
        lock (_consoleLock)
        {
            Console.Write($"\r[LIVE] {summary.Timestamp:HH:mm:ss} | " +
                          $"PPS: {summary.PacketsPerSecond:F1} | " +
                          $"BPS: {FormatBytes((long)summary.BytesPerSecond)}/s | " +
                          $"Active Flows: {summary.ActiveFlowCount} | " +
                          $"TCP: {summary.TcpShare:P0} UDP: {summary.UdpShare:P0} ICMP: {summary.IcmpShare:P0}   ");
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
using System.Text.Json;

namespace PolarisSentinel.Core.Models;

// Serializes the 20 ML features plus the TCP flag counters into the alert's snapshot column.
public static class FlowSnapshot
{
    // The 20 ML feature names in the order the models expect.
    public static readonly string[] FeatureNames =
    {
        "flow_duration_ms",
        "total_fwd_packets",
        "total_bwd_packets",
        "total_fwd_bytes",
        "total_bwd_bytes",
        "pkt_len_min",
        "pkt_len_max",
        "pkt_len_mean",
        "pkt_len_std",
        "fwd_iat_mean_ms",
        "fwd_iat_std_ms",
        "fwd_iat_max_ms",
        "fwd_iat_min_ms",
        "bwd_iat_mean_ms",
        "bwd_iat_std_ms",
        "bwd_iat_max_ms",
        "bwd_iat_min_ms",
        "flow_bytes_per_ms",
        "flow_pkts_per_ms",
        "down_up_ratio"
    };

    public static string Create(FlowFeatureVector flow)
    {
        var values = new Dictionary<string, float>();
        for (int i = 0; i < FeatureNames.Length && i < flow.Features.Length; i++)
        {
            values[FeatureNames[i]] = flow.Features[i];
        }

        values["syn_count"] = flow.SynCount;
        values["ack_count"] = flow.AckCount;
        values["fin_count"] = flow.FinCount;
        values["rst_count"] = flow.RstCount;
        values["psh_count"] = flow.PshCount;

        return JsonSerializer.Serialize(values);
    }

    // Returns the stored snapshot as an ordered list for the alert detail page.
    public static IReadOnlyList<KeyValuePair<string, float>> Read(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return Array.Empty<KeyValuePair<string, float>>();
        }

        var values = JsonSerializer.Deserialize<Dictionary<string, float>>(json) ?? new();
        var ordered = new List<KeyValuePair<string, float>>();
        foreach (string name in FeatureNames)
        {
            if (values.TryGetValue(name, out float value))
            {
                ordered.Add(new(name, value));
            }
        }

        foreach (string flag in new[] { "syn_count", "ack_count", "fin_count", "rst_count", "psh_count" })
        {
            if (values.TryGetValue(flag, out float value))
            {
                ordered.Add(new(flag, value));
            }
        }

        return ordered;
    }
}

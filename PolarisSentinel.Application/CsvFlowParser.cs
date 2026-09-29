using System.Globalization;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Application;

// Parses a labeled CIC-IDS-2017 style CSV into flows for offline evaluation.
public static class CsvFlowParser
{
    // The label column accepted in the uploaded dataset.
    public const string LabelColumn = "label";

    public static bool TryParse(string content, out IReadOnlyList<LabeledFlow> flows, out string? error)
    {
        flows = Array.Empty<LabeledFlow>();
        error = null;

        var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.TrimEnd('\r'))
            .Where(l => !string.IsNullOrWhiteSpace(l))
            .ToList();

        if (lines.Count < 2)
        {
            error = "The CSV must contain a header row and at least one data row.";
            return false;
        }

        var headers = SplitCsv(lines[0]);
        var index = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < headers.Count; i++)
        {
            index[headers[i].Trim()] = i;
        }

        var missing = FlowSnapshot.FeatureNames.Where(f => !index.ContainsKey(f)).ToList();
        if (!index.ContainsKey(LabelColumn))
        {
            missing.Add(LabelColumn);
        }
        if (missing.Count > 0)
        {
            error = "Missing required column(s): " + string.Join(", ", missing);
            return false;
        }

        var parsed = new List<LabeledFlow>();
        for (int row = 1; row < lines.Count; row++)
        {
            var cells = SplitCsv(lines[row]);
            if (cells.Count < headers.Count)
            {
                error = $"Row {row + 1} has {cells.Count} column(s); expected {headers.Count}.";
                return false;
            }

            var features = new float[FlowSnapshot.FeatureNames.Length];
            for (int i = 0; i < FlowSnapshot.FeatureNames.Length; i++)
            {
                string raw = cells[index[FlowSnapshot.FeatureNames[i]]];
                // 模型输入必须是有限数值。
                // Model inputs must be finite numbers.
                if (!float.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out float value) || !float.IsFinite(value))
                {
                    error = $"Row {row + 1}: '{raw}' is not a valid number for {FlowSnapshot.FeatureNames[i]}.";
                    return false;
                }
                features[i] = value;
            }

            string label = cells[index[LabelColumn]].Trim();
            parsed.Add(new LabeledFlow
            {
                Flow = new FlowFeatureVector
                {
                    Features = features,
                    SourceIp = "0.0.0.0",
                    SourcePort = 0,
                    DestinationIp = "0.0.0.0",
                    DestinationPort = 0,
                    Protocol = ProtocolNumbers.Tcp,
                    FlowStartTime = DateTime.UnixEpoch,
                    FlowEndTime = DateTime.UnixEpoch
                },
                IsMalicious = !string.Equals(label, AttackTypes.Benign, StringComparison.OrdinalIgnoreCase)
            });
        }

        flows = parsed;
        return true;
    }

    // Minimal CSV splitter: handles quoted fields but not embedded newlines.
    private static List<string> SplitCsv(string line)
    {
        var cells = new List<string>();
        var current = new System.Text.StringBuilder();
        bool quoted = false;

        foreach (char c in line)
        {
            if (c == '"')
            {
                quoted = !quoted;
            }
            else if (c == ',' && !quoted)
            {
                cells.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }

        cells.Add(current.ToString());
        return cells;
    }
}

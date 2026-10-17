using System.Globalization;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Application.Evaluation;

public static class CsvFlowParser
{
    public const string LabelColumn = "label";

    public static bool TryParse(string content, out IReadOnlyList<LabeledFlow> flows, out string? error, out int skippedRows)
    {
        flows = Array.Empty<LabeledFlow>();
        error = null;
        skippedRows = 0;

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
            string expected =
                $"Expected the export schema: {FlowSnapshot.FeatureNames.Length} feature columns named "
                + string.Join(", ", FlowSnapshot.FeatureNames)
                + $", plus a '{LabelColumn}' column. See ml/artifacts/cic_demo_dataset.csv for the exact header.";

            error = missing.Count >= FlowSnapshot.FeatureNames.Length
                ? $"The CSV header does not match the expected column names. {expected} Header found instead: {DescribeHeaders(headers)}"
                : $"Missing required column(s): {string.Join(", ", missing)}. {expected}";

            return false;
        }

        int labelColumn = index[LabelColumn];
        var parsed = new List<LabeledFlow>();

        for (int row = 1; row < lines.Count; row++)
        {
            var cells = SplitCsv(lines[row]);

            if (!TryReadFeatures(cells, index, out float[] features) ||
                labelColumn >= cells.Count ||
                string.IsNullOrWhiteSpace(cells[labelColumn]))
            {
                skippedRows++;
                continue;
            }

            string label = cells[labelColumn].Trim();
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

        if (parsed.Count == 0)
        {
            error = skippedRows > 0
                ? $"All {skippedRows} data row(s) were unusable. Every one of the 20 feature columns must hold a finite number and the label column must not be empty."
                : "The CSV contains a header row but no data rows.";
            return false;
        }

        flows = parsed;
        return true;
    }

    private static bool TryReadFeatures(List<string> cells, Dictionary<string, int> index, out float[] features)
    {
        features = new float[FlowSnapshot.FeatureNames.Length];

        for (int i = 0; i < features.Length; i++)
        {
            int column = index[FlowSnapshot.FeatureNames[i]];

            if (column >= cells.Count || !TryReadFloat(cells[column], out float value))
            {
                return false;
            }

            features[i] = value;
        }

        return true;
    }

    private static string DescribeHeaders(List<string> headers)
    {
        const int shown = 8;

        string listed = string.Join(", ", headers.Take(shown).Select(h => h.Trim()));
        return headers.Count > shown
            ? $"{listed} and {headers.Count - shown} more ({headers.Count} column(s) in total)"
            : $"{listed} ({headers.Count} column(s) in total)";
    }

    private static bool TryReadFloat(string raw, out float value)
    {
        value = 0f;

        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        return float.TryParse(raw.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out value) && float.IsFinite(value);
    }

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

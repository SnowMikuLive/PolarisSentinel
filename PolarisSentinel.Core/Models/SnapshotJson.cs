using System.Text.Json;

namespace PolarisSentinel.Core.Models;

// Shared JSON (de)serialization for the alert snapshot columns, which all store a
// string-keyed float dictionary.
internal static class SnapshotJson
{
    public static string Serialize(IReadOnlyDictionary<string, float> values) =>
        JsonSerializer.Serialize(values);

    public static Dictionary<string, float> Read(string? json) =>
        string.IsNullOrWhiteSpace(json)
            ? new Dictionary<string, float>()
            : JsonSerializer.Deserialize<Dictionary<string, float>>(json) ?? new Dictionary<string, float>();
}

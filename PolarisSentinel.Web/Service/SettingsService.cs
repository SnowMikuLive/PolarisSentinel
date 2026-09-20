using System.Text.Json;
using PolarisSentinel.Core.Models;
using PolarisSentinel.FirewallEnforement;

namespace PolarisSentinel.Web.Service;

// Holds runtime settings (timezone + NIC) and persists them to appsettings.json.
public class SettingsService
{
    public const string Utc = "UTC";
    public const string SystemLocal = "SystemLocal";

    private readonly IConfiguration _config;
    private readonly IWebHostEnvironment _env;
    private readonly object _lock = new();

    public SettingsService(IConfiguration config, IWebHostEnvironment env)
    {
        _config = config;
        _env = env;
        TimeZoneId = _config["Settings:TimeZoneId"] ?? Utc;
    }

    // "UTC", "SystemLocal", or an IANA id (e.g. "Asia/Shanghai").
    public string TimeZoneId { get; private set; }

    // IANA timezone ids for the dropdown.
    public static IReadOnlyList<string> AvailableTimeZones =>
        TimeZoneInfo.GetSystemTimeZones().Select(tz => tz.Id).ToList();

    // Convert a UTC timestamp to the configured display timezone.
    public DateTime ConvertToDisplay(DateTime utc)
    {
        var dt = utc.Kind == DateTimeKind.Unspecified
            ? DateTime.SpecifyKind(utc, DateTimeKind.Utc)
            : utc;

        if (TimeZoneId == Utc)
        {
            return dt;
        }

        if (TimeZoneId == SystemLocal)
        {
            return dt.ToLocalTime();
        }

        var info = TimeZoneInfo.FindSystemTimeZoneById(TimeZoneId);
        return TimeZoneInfo.ConvertTimeFromUtc(dt, info);
    }

    // Format helper used by views.
    public string Format(DateTime utc) => ConvertToDisplay(utc).ToString("yyyy-MM-dd HH:mm:ss");

    // Persist the timezone to appsettings.json and keep it hot in memory.
    public bool SetTimeZone(string timeZoneId)
    {
        if (timeZoneId != Utc && timeZoneId != SystemLocal)
        {
            try
            {
                _ = TimeZoneInfo.FindSystemTimeZoneById(timeZoneId);
            }
            catch (TimeZoneNotFoundException)
            {
                return false;
            }
        }

        lock (_lock)
        {
            TimeZoneId = timeZoneId;
        }

        SaveSection("Settings", "TimeZoneId", JsonSerializer.SerializeToElement(timeZoneId));
        return true;
    }

    // Persist editable policy settings to the PolicySettings section.
    public void SavePolicySettings(Policy settings)
    {
        SaveSection("PolicySettings", null, JsonSerializer.SerializeToElement(settings));
    }

    // Persist firewall options to the Firewall section.
    public void SaveFirewallOptions(FirewallOptions options)
    {
        SaveSection("Firewall", null, JsonSerializer.SerializeToElement(options));
    }

    // Merge a single key (or a whole section when key is null) into appsettings.json.
    private void SaveSection(string section, string? key, JsonElement value)
    {
        var path = Path.Combine(_env.ContentRootPath, "appsettings.json");
        try
        {
            var json = File.ReadAllText(path);
            var root = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
            if (root == null)
            {
                return;
            }

            if (key == null)
            {
                root[section] = value;
            }
            else
            {
                var sectionMap = root.TryGetValue(section, out var el) && el.ValueKind == JsonValueKind.Object
                    ? JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(el.GetRawText()) ?? new()
                    : new Dictionary<string, JsonElement>();
                sectionMap[key] = value;
                root[section] = JsonSerializer.SerializeToElement(sectionMap);
            }

            File.WriteAllText(path, JsonSerializer.Serialize(root, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            // Persistence failure must not break the running app.
            System.Diagnostics.Debug.WriteLine($"Failed to persist {section}: {ex.Message}");
        }
    }
}

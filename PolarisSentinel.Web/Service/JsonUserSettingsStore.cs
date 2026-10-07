using System.Text.Json;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Service;

// Persists user choices to a JSON file under the user's local app data, so dry-run,
// model combination and capture device follow the user across restarts. Reading a
// missing or corrupt file degrades to defaults instead of failing startup.
public sealed class JsonUserSettingsStore : IUserSettingsStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new() { WriteIndented = true };

    private readonly object _lock = new();
    private readonly string _path;
    private readonly ILogger<JsonUserSettingsStore> _logger;

    public JsonUserSettingsStore(ILogger<JsonUserSettingsStore> logger, string? path = null)
    {
        _logger = logger;
        _path = path ?? DefaultPath();
    }

    private static string DefaultPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "PolarisSentinel",
        "user-settings.json");

    public UserSettings Read()
    {
        lock (_lock)
        {
            return ReadCore();
        }
    }

    public void Update(Action<UserSettings> mutate)
    {
        lock (_lock)
        {
            var settings = ReadCore();
            mutate(settings);
            WriteCore(settings);
        }
    }

    private UserSettings ReadCore()
    {
        try
        {
            if (File.Exists(_path))
            {
                return JsonSerializer.Deserialize<UserSettings>(File.ReadAllText(_path)) ?? new UserSettings();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read user settings from {Path}; using defaults.", _path);
        }

        return new UserSettings();
    }

    private void WriteCore(UserSettings settings)
    {
        try
        {
            string? directory = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(_path, JsonSerializer.Serialize(settings, SerializerOptions));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not persist user settings to {Path}.", _path);
        }
    }
}

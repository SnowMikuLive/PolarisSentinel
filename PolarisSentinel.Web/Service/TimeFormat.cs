namespace PolarisSentinel.Web.Service;

// Formats timestamps for display. All times are stored in local system time.
public static class TimeFormat
{
    public static string Format(DateTime value) => value.ToString("yyyy-MM-dd HH:mm:ss");
}

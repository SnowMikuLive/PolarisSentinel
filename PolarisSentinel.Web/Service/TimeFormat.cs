namespace PolarisSentinel.Web.Service;

// Formats timestamps for display. All times are stored in local system time.
public static class TimeFormat
{
    public static string Format(DateTime value) => value.ToString("yyyy-MM-dd HH:mm:ss");

    public static string Relative(DateTime value)
    {
        var delta = value - DateTime.Now;
        var past = delta < TimeSpan.Zero;
        var span = past ? delta.Negate() : delta;

        string amount;
        if (span.TotalSeconds < 60)
        {
            amount = $"{(int)span.TotalSeconds}s";
        }
        else if (span.TotalMinutes < 60)
        {
            amount = $"{(int)span.TotalMinutes}m";
        }
        else if (span.TotalHours < 24)
        {
            amount = $"{(int)span.TotalHours}h";
        }
        else
        {
            amount = $"{(int)span.TotalDays}d";
        }

        return past ? $"{amount} ago" : $"in {amount}";
    }

    public static bool IsWithin(DateTime? value, TimeSpan window)
    {
        if (value is not { } target)
        {
            return false;
        }

        var now = DateTime.Now;
        return target > now && target - now <= window;
    }
}

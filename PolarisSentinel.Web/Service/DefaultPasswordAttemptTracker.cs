namespace PolarisSentinel.Web.Service;

// Counts failed sign-ins that used the configured default password within a sliding hour.
// A hidden recovery path uses this to reset the admin account back to the default after the
// default password has been entered too many times in one hour.
public class DefaultPasswordAttemptTracker
{
    private const int Threshold = 10;
    private static readonly TimeSpan Window = TimeSpan.FromHours(1);

    private readonly object _lock = new();
    private readonly Queue<DateTime> _attempts = new();

    public bool Record(DateTime now)
    {
        lock (_lock)
        {
            var cutoff = now - Window;
            while (_attempts.Count > 0 && _attempts.Peek() < cutoff)
            {
                _attempts.Dequeue();
            }

            _attempts.Enqueue(now);

            if (_attempts.Count > Threshold)
            {
                _attempts.Clear();
                return true;
            }

            return false;
        }
    }
}

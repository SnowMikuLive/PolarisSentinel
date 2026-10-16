using System.Text;
using Microsoft.Extensions.Logging;

namespace PolarisSentinel.Web.Logging;

public sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly object _lock = new();
    private readonly string _directory;
    private readonly int _retainedFileCount;
    private readonly LogLevel _minimumLevel;

    private StreamWriter? _writer;
    private string? _currentPath;

    public FileLoggerProvider(string directory, int retainedFileCount = 7, LogLevel minimumLevel = LogLevel.Information)
    {
        _directory = directory;
        _retainedFileCount = retainedFileCount < 1 ? 1 : retainedFileCount;
        _minimumLevel = minimumLevel;
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);

    public void Dispose()
    {
        lock (_lock)
        {
            _writer?.Dispose();
            _writer = null;
            _currentPath = null;
        }
    }

    internal bool IsEnabled(LogLevel level, string category)
    {
        if (level == LogLevel.None || level < _minimumLevel)
        {
            return false;
        }

        if (category.StartsWith("Microsoft.", StringComparison.Ordinal) && level < LogLevel.Warning)
        {
            return false;
        }

        return true;
    }

    internal void Write(string category, LogLevel level, string message, Exception? exception)
    {
        lock (_lock)
        {
            try
            {
                var writer = EnsureWriter();
                if (writer is null)
                {
                    return;
                }

                writer.Write(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"));
                writer.Write(" [");
                writer.Write(ShortLevel(level));
                writer.Write("] ");
                writer.Write(category);
                writer.Write(": ");
                writer.WriteLine(message);

                if (exception is not null)
                {
                    writer.WriteLine(exception);
                }
            }
            catch (Exception)
            {
            }
        }
    }

    private StreamWriter? EnsureWriter()
    {
        string path = Path.Combine(_directory, $"polaris-{DateTime.Now:yyyyMMdd}.log");

        if (_writer is not null && string.Equals(_currentPath, path, StringComparison.OrdinalIgnoreCase))
        {
            return _writer;
        }

        _writer?.Dispose();
        Directory.CreateDirectory(_directory);

        _writer = new StreamWriter(
            new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
        {
            AutoFlush = true
        };

        _currentPath = path;
        Prune();
        return _writer;
    }

    private void Prune()
    {
        try
        {
            var files = new DirectoryInfo(_directory)
                .GetFiles("polaris-*.log")
                .OrderByDescending(f => f.Name)
                .Skip(_retainedFileCount)
                .ToList();

            foreach (var file in files)
            {
                file.Delete();
            }
        }
        catch (Exception)
        {
        }
    }

    private static string ShortLevel(LogLevel level) => level switch
    {
        LogLevel.Trace => "TRC",
        LogLevel.Debug => "DBG",
        LogLevel.Information => "INF",
        LogLevel.Warning => "WRN",
        LogLevel.Error => "ERR",
        LogLevel.Critical => "CRT",
        _ => "???"
    };

    private sealed class FileLogger : ILogger
    {
        private readonly FileLoggerProvider _provider;
        private readonly string _category;

        public FileLogger(FileLoggerProvider provider, string category)
        {
            _provider = provider;
            _category = category;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => _provider.IsEnabled(logLevel, _category);

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel) || formatter is null)
            {
                return;
            }

            _provider.Write(_category, logLevel, formatter(state, exception), exception);
        }
    }
}

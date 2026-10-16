using PolarisSentinel.Application;
using PolarisSentinel.Application.Evaluation;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Service
{

    public class TestDatasetService
    {
        private readonly object _lock = new();
        private IReadOnlyList<LabeledFlow> _rows = Array.Empty<LabeledFlow>();

        public string? FileName { get; private set; }

        public int Count
        {
            get
            {
                lock (_lock)
                {
                    return _rows.Count;
                }
            }
        }

        public bool Load(string fileName, string content, out string? error, out int skippedRows)
        {
            if (!CsvFlowParser.TryParse(content, out var rows, out error, out skippedRows))
            {
                return false;
            }

            lock (_lock)
            {
                _rows = rows;
                FileName = fileName;
            }
            return true;
        }

        public IReadOnlyList<LabeledFlow> GetPage(int startIndex, int count)
        {
            lock (_lock)
            {
                return _rows.Skip(startIndex).Take(count).ToList();
            }
        }

        public LabeledFlow? Get(int index)
        {
            lock (_lock)
            {
                return index >= 0 && index < _rows.Count ? _rows[index] : null;
            }
        }
    }
}

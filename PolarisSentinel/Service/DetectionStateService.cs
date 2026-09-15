using PolarisSentinel.Core.Constants;

namespace PolarisSentinel.Web.Service
{
    // 推送给 SignalR 和状态 API 的统一记录
    // Unified record for SignalR push and state API
    public record DetectionRecord(
        Guid AlertId,
        string SourceIp,
        string DestinationIp,
        int DestinationPort,
        string AttackType,
        float Confidence,
        string Action,
        string DecidedAt,
        string Reason,
        string Source,
        string? RuleName);

    // 检测状态服务（单例），维护累计计数和最近决策
    // Singleton detection state service with counters and recent decisions
    public class DetectionStateService
    {
        private const int MaxHistory = 50;

        private readonly object _lock = new();

        public int Flows { get; private set; }
        public int Benign { get; private set; }
        public int Monitor { get; private set; }
        public int Block { get; private set; }

        private readonly List<DetectionRecord> _recent = new();

        public void Record(DetectionRecord record)
        {
            lock (_lock)
            {
                Flows++;

                if (record.AttackType == AttackTypes.Benign)
                {
                    Benign++;
                    return;
                }

                if (record.Action == "Block") Block++;
                else if (record.Action == "Monitor") Monitor++;

                _recent.Insert(0, record);

                // 只保留最近 N 条
                // Keep only the most recent N records
                if (_recent.Count > MaxHistory)
                {
                    _recent.RemoveAt(_recent.Count - 1);
                }
            }
        }

        public object GetSnapshot()
        {
            lock (_lock)
            {
                return new
                {
                    flows = Flows,
                    benign = Benign,
                    monitor = Monitor,
                    block = Block,
                    recent = _recent.ToArray()
                };
            }
        }
    }
}

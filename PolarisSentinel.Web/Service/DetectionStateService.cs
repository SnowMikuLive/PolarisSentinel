using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Service
{
    // Unified record pushed to SignalR and returned by the state API.
    public record DetectionRecord(
        string AlertId,
        string SourceIp,
        int SourcePort,
        string DestinationIp,
        int DestinationPort,
        string AttackType,
        float? ConfidenceScore,
        string Action,
        string CreatedAt,
        string Reason,
        string Source,
        string? RuleName,
        string Verdict,
        string DecisionReason,
        string DecisionText);

    // Singleton runtime counters and the live traffic window for the current day.
    public class DetectionStateService
    {
        public const int MaxLiveRecords = 20000;

        public const int MaxRecentRecords = 1000;

        private readonly object _lock = new();
        private readonly Queue<(DateTime Timestamp, DetectionRecord Record)> _live = new();

        public int CapturedFlowCount { get; private set; }
        public int AlertCount { get; private set; }
        public int NormalCount { get; private set; }
        public int SuspiciousCount { get; private set; }
        public int MaliciousCount { get; private set; }

        public int BlockedCount { get; private set; }

        public DetectionRecord Record(DetectionOutcome outcome)
        {
            var now = DateTime.Now;

            var record = new DetectionRecord(
                outcome.Alert?.Id ?? string.Empty,
                outcome.Alert?.SourceIp ?? outcome.SourceIp,
                outcome.Alert?.SourcePort ?? outcome.SourcePort,
                outcome.Alert?.DestinationIp ?? outcome.DestinationIp,
                outcome.Alert?.DestinationPort ?? outcome.DestinationPort,
                outcome.Alert?.AttackType ?? AttackTypes.Benign,
                outcome.Alert?.ConfidenceScore,
                outcome.Decision?.Action.ToString() ?? "Monitor",
                now.ToString("yyyy-MM-dd HH:mm:ss"),
                outcome.Alert?.Description ?? outcome.Decision?.Reason ?? outcome.Description ?? string.Empty,
                outcome.Alert?.DetectionSource.ToString() ?? DetectionSource.None.ToString(),
                outcome.Rule?.Name,
                outcome.Verdict.ToString(),
                outcome.Decision?.Reason ?? string.Empty,
                outcome.Decision?.ReasonText ?? string.Empty);

            lock (_lock)
            {
                CapturedFlowCount++;

                switch (outcome.Verdict)
                {
                    case TrafficVerdict.Normal:
                        NormalCount++;
                        break;
                    case TrafficVerdict.Suspicious:
                        SuspiciousCount++;
                        break;
                    case TrafficVerdict.Malicious:
                        MaliciousCount++;
                        break;
                    case TrafficVerdict.Blocked:
                        BlockedCount++;
                        break;
                }

                if (outcome.Alert is not null)
                {
                    AlertCount++;
                }

                _live.Enqueue((now, record));

                while (_live.Count > MaxLiveRecords)
                {
                    _live.Dequeue();
                }
            }

            return record;
        }

        public void Clear()
        {
            lock (_lock)
            {
                _live.Clear();
                CapturedFlowCount = 0;
                AlertCount = 0;
                NormalCount = 0;
                SuspiciousCount = 0;
                MaliciousCount = 0;
                BlockedCount = 0;
            }
        }

        public void Restore(IReadOnlyList<TrafficRecord> records)
        {
            lock (_lock)
            {
                _live.Clear();
                var restored = new List<(DateTime Timestamp, DetectionRecord Record)>();

                foreach (var record in records)
                {
                    var detection = new DetectionRecord(
                        record.AlertId,
                        record.SourceIp,
                        record.SourcePort,
                        record.DestinationIp,
                        record.DestinationPort,
                        record.AttackType,
                        record.ConfidenceScore,
                        record.Action,
                        record.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss"),
                        record.Reason,
                        record.Source,
                        record.RuleName,
                        record.Verdict,
                        string.Empty,
                        string.Empty);

                    restored.Add((record.CreatedAt, detection));

                    CapturedFlowCount++;
                    switch (record.Verdict)
                    {
                        case nameof(TrafficVerdict.Normal):
                            NormalCount++;
                            break;
                        case nameof(TrafficVerdict.Suspicious):
                            SuspiciousCount++;
                            break;
                        case nameof(TrafficVerdict.Malicious):
                            MaliciousCount++;
                            break;
                        case nameof(TrafficVerdict.Blocked):
                            BlockedCount++;
                            break;
                    }

                    if (!string.IsNullOrEmpty(record.AlertId))
                    {
                        AlertCount++;
                    }
                }

                foreach (var entry in restored.OrderBy(e => e.Timestamp))
                {
                    _live.Enqueue(entry);
                }

                while (_live.Count > MaxLiveRecords)
                {
                    _live.Dequeue();
                }
            }
        }

        public int PruneExpired(DateTime now)
        {
            var cutoff = now.Date;
            lock (_lock)
            {
                int before = _live.Count;
                while (_live.Count > 0 && _live.Peek().Timestamp < cutoff)
                {
                    _live.Dequeue();
                }
                return before - _live.Count;
            }
        }

        // activeRules is supplied by the caller (the firewall owns the rule store) so this
        // service stays free of any firewall dependency.
        public object GetSnapshot(int activeRules)
        {
            var now = DateTime.Now;
            PruneExpired(now);

            lock (_lock)
            {
                return new
                {
                    capturedFlows = CapturedFlowCount,
                    alerts = AlertCount,
                    activeRules,
                    normal = NormalCount,
                    suspicious = SuspiciousCount,
                    malicious = MaliciousCount,
                    blocked = BlockedCount,
                    recent = _live.Reverse().Take(MaxRecentRecords).Select(e => e.Record).ToArray()
                };
            }
        }

        public IReadOnlyList<DetectionRecord> GetLiveRecords()
        {
            var now = DateTime.Now;
            PruneExpired(now);

            lock (_lock)
            {
                return _live.Select(e => e.Record).ToArray();
            }
        }

        public object GetTrafficSeries()
        {
            var now = DateTime.Now;
            PruneExpired(now);

            lock (_lock)
            {
                var buckets = _live
                    .GroupBy(e => new DateTime(
                        e.Timestamp.Year, e.Timestamp.Month, e.Timestamp.Day,
                        e.Timestamp.Hour, e.Timestamp.Minute, 0))
                    .OrderBy(g => g.Key)
                    .Select(g => new
                    {
                        time = g.Key.ToString("HH:mm"),
                        normal = g.Count(e => e.Record.Verdict == nameof(TrafficVerdict.Normal)),
                        blocked = g.Count(e => e.Record.Verdict == nameof(TrafficVerdict.Blocked))
                    })
                    .ToArray();

                return new { points = buckets };
            }
        }

        public static TrafficRecord ToTrafficRecord(DetectionRecord record)
        {
            return new TrafficRecord
            {
                AlertId = record.AlertId,
                SourceIp = record.SourceIp,
                SourcePort = record.SourcePort,
                DestinationIp = record.DestinationIp,
                DestinationPort = record.DestinationPort,
                AttackType = record.AttackType,
                ConfidenceScore = record.ConfidenceScore,
                Action = record.Action,
                Reason = record.Reason,
                Source = record.Source,
                RuleName = record.RuleName,
                Verdict = record.Verdict,
                CreatedAt = DateTime.TryParse(record.CreatedAt, out var parsed) ? parsed : DateTime.Now
            };
        }
    }
}

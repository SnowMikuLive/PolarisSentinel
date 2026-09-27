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
        string Verdict);

    // Singleton runtime counters and the live traffic window for the current day.
    public class DetectionStateService
    {
        // Hard cap so a flood cannot grow the history without bound.
        public const int MaxLiveRecords = 20000;

        private readonly object _lock = new();
        private readonly List<(DateTime Timestamp, DetectionRecord Record)> _live = new();

        // Application-lifetime counters, reset only when the application restarts.
        public int CapturedFlowCount { get; private set; }
        public int AlertCount { get; private set; }
        public int NormalCount { get; private set; }
        public int SuspiciousCount { get; private set; }
        public int MaliciousCount { get; private set; }

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
                outcome.Verdict.ToString());

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
                }

                if (outcome.Alert is not null)
                {
                    AlertCount++;
                }

                // Every classified flow is kept, so the monitor shows the full window
                // rather than only the alerts.
                _live.Insert(0, (now, record));

                if (_live.Count > MaxLiveRecords)
                {
                    _live.RemoveRange(MaxLiveRecords, _live.Count - MaxLiveRecords);
                }
            }

            return record;
        }

        // Seeds the window with records restored from the database (today's history).
        // Counters are rebuilt from the restored records so the cards match the table.
        public void Restore(IReadOnlyList<TrafficRecord> records)
        {
            lock (_lock)
            {
                _live.Clear();

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
                        record.Verdict);

                    _live.Add((record.CreatedAt, detection));

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
                    }

                    if (!string.IsNullOrEmpty(record.AlertId))
                    {
                        AlertCount++;
                    }
                }

                // Keep newest first, matching the live insert order.
                _live.Sort((a, b) => b.Timestamp.CompareTo(a.Timestamp));

                if (_live.Count > MaxLiveRecords)
                {
                    _live.RemoveRange(MaxLiveRecords, _live.Count - MaxLiveRecords);
                }
            }
        }

        // Drops records created before local midnight. Called by the sweeper and on each read.
        public int PruneExpired(DateTime now)
        {
            var cutoff = now.Date;
            lock (_lock)
            {
                int before = _live.Count;
                int keep = _live.FindIndex(entry => entry.Timestamp >= cutoff);
                if (keep < 0)
                {
                    _live.Clear();
                }
                else if (keep > 0)
                {
                    _live.RemoveRange(keep, _live.Count - keep);
                }
                return before - _live.Count;
            }
        }

        public object GetSnapshot()
        {
            var now = DateTime.Now;
            PruneExpired(now);

            lock (_lock)
            {
                return new
                {
                    capturedFlows = CapturedFlowCount,
                    alerts = AlertCount,
                    normal = NormalCount,
                    suspicious = SuspiciousCount,
                    malicious = MaliciousCount,
                    recent = _live.Select(e => e.Record).ToArray()
                };
            }
        }

        // Per-minute flow counts for the whole day, oldest first, for the line chart.
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
                        count = g.Count()
                    })
                    .ToArray();

                return new { points = buckets };
            }
        }

        // Converts a live record into a persistable row.
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

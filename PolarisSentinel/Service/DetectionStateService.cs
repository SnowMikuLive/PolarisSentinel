using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Core.Constants;

namespace PolarisSentinel.Web.Service
{
    //Detection record DOT. It can used to push both state storage and SignalR
    public record DetectionRecord(
        Guid AlertId,
        string SourceIp,
        string DestinationIp,
        int DestinationPort,
        string AttackType,
        float Confidence,
        string Action,
        string DecidedAt,
        string Reason);

    //detecte whole state service (singleton),stores cumulative counters and recent decisions
    public class DetectionStateService
    {
        private const int MaxHistory = 50;

        //Create a lock object, Make sure only one thread enters the critical zone at a time
        private readonly object _lock = new();

        // Cumulative counters
        public int Flows { get; private set; }
        public int Benign { get; private set; }
        public int Monitor { get; private set; }
        public int Block { get; private set; }

        //Recent decisions list (newest first)
        private readonly List<DetectionRecord> _recent = new();

        //the one decision recorded
        public void Record(DetectionRecord record)
        {
            lock (_lock)
            {
                //Total flow count +1
                Flows++;

                //Counters are accumulated according to attack type and action
                if (record.AttackType == AttackTypes.Benign)
                {
                    Benign++;
                    return;
                }
                //else
                //{
                    if (record.Action == "Block") Block++;
                    else if (record.Action == "Monitor") Monitor++;
                //}

                //Insert the new record to the very front of the recent list
                _recent.Insert(0, record);

                //If the list exceeds the maximum capacity, delete the oldest entry
                if (_recent.Count > MaxHistory)
                {
                    _recent.RemoveAt(_recent.Count -1);
                }
            }
        }

        //Return current state snapshot (for API)
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

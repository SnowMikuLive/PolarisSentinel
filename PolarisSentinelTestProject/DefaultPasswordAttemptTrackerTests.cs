using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Web.Service;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class DefaultPasswordAttemptTrackerTests
{
    private static readonly DateTime Start = new(2026, 10, 13, 12, 0, 0, DateTimeKind.Utc);

    [TestMethod]
    public void Record_MoreThanTenAttemptsWithinAnHour_TriggersReset()
    {
        var tracker = new DefaultPasswordAttemptTracker();

        for (int i = 0; i < 10; i++)
        {
            Assert.IsFalse(tracker.Record(Start.AddMinutes(i)));
        }

        Assert.IsTrue(tracker.Record(Start.AddMinutes(10)));
    }

    [TestMethod]
    public void Record_AttemptsSpreadBeyondWindow_DoNotTrigger()
    {
        var tracker = new DefaultPasswordAttemptTracker();

        for (int i = 0; i < 10; i++)
        {
            Assert.IsFalse(tracker.Record(Start.AddMinutes(i * 10)));
        }

        Assert.IsFalse(tracker.Record(Start.AddMinutes(100)));
    }
}

using PolarisSentinel.Application;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Models;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class EntityIdConcurrencyTests
{
    [TestMethod]
    [DataRow(EntityIds.AlertPrefix)]
    [DataRow(EntityIds.RulePrefix)]
    [DataRow(EntityIds.PolicyPrefix)]
    public void Next_ConcurrentCallsWithUnchangedStoredIds_ShouldNotReuseNumbers(string prefix)
    {
        string[] storedIds = { $"{prefix}1000" };
        var ids = new string[256];

        // All requests see the same database snapshot; none of their new ids is saved yet.
        Parallel.For(0, ids.Length, i =>
            ids[i] = EntityIds.Next(storedIds, prefix, number => $"{prefix}{number}"));

        Assert.HasCount(ids.Length, ids.Distinct().ToArray());
        Assert.IsTrue(ids.All(id => int.Parse(id.AsSpan(prefix.Length)) > 1000));
    }

    [TestMethod]
    public void Next_ShouldFollowStoredMaximumAndKeepUnsavedReservations()
    {
        const string prefix = "test-resume-";
        var first = EntityIds.ReserveNextNumber(10, prefix);
        var second = EntityIds.ReserveNextNumber(0, prefix);
        var third = EntityIds.ReserveNextNumber(second + 100, prefix);

        Assert.IsGreaterThan(10, first);
        Assert.AreEqual(first + 1, second);
        Assert.AreEqual(second + 101, third);
    }

    [TestMethod]
    public void NextPolicyId_ConcurrentServiceInstances_ShouldNotReuseUnsavedIds()
    {
        var unitOfWork = new FakeUnitOfWork();
        unitOfWork.Policies.Add(new Policy { Id = "P-1000" });
        var ids = new string[128];

        Parallel.For(0, ids.Length, i =>
        {
            var service = new PolicyManagementService(unitOfWork);
            ids[i] = service.NextPolicyIdAsync().GetAwaiter().GetResult();
        });

        Assert.HasCount(ids.Length, ids.Distinct().ToArray());
        Assert.IsTrue(ids.All(id => int.Parse(id.AsSpan(EntityIds.PolicyPrefix.Length)) > 1000));
    }
}
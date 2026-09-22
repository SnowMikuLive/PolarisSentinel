using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;
using PolarisSentinel.FirewallEnforement;
using PolarisSentinel.Web.Controllers;
using PolarisSentinel.Web.Service;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class FirewallServiceUnitTest
    {
        #region Rules Page Backing Tests

        //Rules页面读取实时规则（仅托管规则）
        //Rules page reads live managed rules
        [TestMethod]
        public void FirewallRulesPage_GetAllRules_ShouldReturnCreatedRule()
        {
            // Arrange
            var engine = CreateEngine(new FakeTimeProvider());
            engine.BlockIp(CreateDecision(), TimeSpan.FromMinutes(60));

            // Act
            var rules = engine.GetAllRules().ToList();

            // Assert
            Assert.HasCount(1, rules);
            Assert.AreEqual("203.0.113.66", rules.Single().RemoteAddress);
        }

        //Rules页面的Remove All删除全部托管规则
        //Rules page Remove All clears every managed rule
        [TestMethod]
        public void FirewallRulesPage_RemoveAll_ShouldRemoveCreatedRules()
        {
            // Arrange
            var engine = CreateEngine(new FakeTimeProvider());
            engine.BlockIp(CreateDecision(), TimeSpan.FromMinutes(60));

            // Act
            int removed = engine.RemoveAllManagedRules();

            // Assert
            Assert.AreEqual(1, removed);
            Assert.IsEmpty(engine.GetAllRules());
        }

        #endregion

        #region Sweeper Tests

        //启动清扫服务时删除已过期规则
        //Remove expired rules when the sweeper starts
        [TestMethod]
        public async Task FirewallRuleSweeper_Start_ShouldRemoveExpiredRule()
        {
            // Arrange
            var clock = new FakeTimeProvider();
            var engine = CreateEngine(clock);
            engine.BlockIp(CreateDecision(), TimeSpan.FromMinutes(1));
            clock.Advance(TimeSpan.FromMinutes(2));
            using var sweeper = new FirewallRuleSweeper(
                engine, Options.Create(new FirewallOptions()), clock);

            // Act
            await sweeper.StartAsync(CancellationToken.None);
            try
            {
                // Assert
                Assert.IsEmpty(engine.GetAllRules());
            }
            finally
            {
                await sweeper.StopAsync(CancellationToken.None);
            }
        }

        #endregion

        #region Helper Methods

        //默认DryRun，测试只操作内存规则
        //Default DryRun keeps test rules in memory
        private WindowsFirewallEnforcer CreateEngine(FakeTimeProvider clock)
        {
            return new WindowsFirewallEnforcer(
                Options.Create(new FirewallOptions()), clock,
                NullLogger<WindowsFirewallEnforcer>.Instance);
        }

<<<<<<< HEAD
        //默认使用RFC 5737文档地址
        //Default uses RFC 5737 documentation addresses
        private Policy CreateDecision()
=======
        // 默认使用 RFC 5737 文档地址
        // Default uses RFC 5737 documentation addresses
        private Alert CreateDecision()
>>>>>>> d47e7ec0c32803f010bc8a3c97a4dc42d392cd92
        {
            return new Alert
            {
                Id = EntityIds.Alert(DetectionSource.RandomForest, 1),
                Action = PolicyAction.Block,
                SourceIp = "203.0.113.66",
                DestinationIp = "192.168.1.10",
                AttackType = AttackTypes.DoS,
                Confidence = 0.95f,
                Source = DetectionSource.RandomForest,
                DecidedAt = DateTime.UtcNow,
                Reason = "test"
            };
        }

        #endregion
    }
}

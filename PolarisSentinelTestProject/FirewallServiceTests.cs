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
        #region Controller Tests

        [TestMethod]
        public void FirewallController_GetRules_ShouldReturnCreatedRule()
        {
            // Arrange
            var engine = CreateEngine(new FakeTimeProvider());
            engine.BlockIp(CreateDecision(), TimeSpan.FromMinutes(60));
            var controller = new FirewallController(engine);

            // Act
            var result = (OkObjectResult)controller.GetRules();
            var rules = (IEnumerable<FirewallRuleInfo>)result.Value!;

            // Assert
            Assert.HasCount(1, rules);
            Assert.AreEqual("203.0.113.66", rules.Single().RemoteAddress);
        }

        [TestMethod]
        public void FirewallController_Rollback_ShouldRemoveCreatedRules()
        {
            // Arrange
            var engine = CreateEngine(new FakeTimeProvider());
            engine.BlockIp(CreateDecision(), TimeSpan.FromMinutes(60));
            var controller = new FirewallController(engine);

            // Act
            var result = controller.Rollback();

            // Assert
            Assert.IsInstanceOfType<OkObjectResult>(result);
            Assert.IsEmpty(engine.GetAllRules());
        }

        #endregion

        #region Sweeper Tests

        // 启动清扫服务时删除已过期规则
        // Remove expired rules when the sweeper starts
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

        // 默认 DryRun，测试只操作内存规则
        // Default DryRun keeps test rules in memory
        private WindowsFirewallEnforcer CreateEngine(FakeTimeProvider clock)
        {
            return new WindowsFirewallEnforcer(
                Options.Create(new FirewallOptions()), clock,
                NullLogger<WindowsFirewallEnforcer>.Instance);
        }

        // 默认使用 RFC 5737 文档地址
        // Default uses RFC 5737 documentation addresses
        private PolicyDecision CreateDecision()
        {
            return new PolicyDecision
            {
                AlertId = Guid.NewGuid(),
                Action = PolicyAction.Block,
                SourceIp = "203.0.113.66",
                AttackType = AttackTypes.DoS,
                Confidence = 0.95f,
                Source = DetectionSource.RandomForest,
                DecidedAt = DateTime.UtcNow
            };
        }

        #endregion
    }
}

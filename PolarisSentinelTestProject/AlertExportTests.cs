using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Web.Controllers;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class AlertExportTests
{
    [TestMethod]
    public async Task EmptyExportShouldContainHeader()
    {
        var controller = new InferenceResultsController(new FakeUnitOfWork());
        var file = (FileContentResult)await controller.Export(CancellationToken.None);

        Assert.AreEqual("text/csv; charset=utf-8", file.ContentType);
        Assert.IsTrue(file.FileDownloadName.EndsWith(".csv"));
        CollectionAssert.AreEqual(Encoding.UTF8.GetPreamble(), file.FileContents.Take(3).ToArray());
        Assert.AreEqual(1, Read(file).Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).Length);
    }

    [TestMethod]
    public async Task ExportShouldPreserveTextAndLinkedAction()
    {
        var uow = new FakeUnitOfWork();
        var alert = CreateAlert();
        alert.Description = "测试, \"quoted\"\nsecond line";
        uow.Alerts.Add(alert);
        uow.Rules.Add(new Rule { Id = "R-1", Name = "PolarisSentinel_Test", AlertId = alert.Id,
            Action = PolicyAction.BlockInboundIp, Status = RuleStatus.Active });
        var controller = new InferenceResultsController(uow);
        var previous = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("fr-FR");
            var file = (FileContentResult)await controller.Export(CancellationToken.None);
            var csv = Read(file);
            StringAssert.Contains(csv, "\"0.95\"");
            StringAssert.Contains(csv, "\"PolarisSentinel_Test\",\"BlockInboundIp\",\"Active\"");
            StringAssert.Contains(csv, "\"测试, \"\"quoted\"\"\nsecond line\"");
        }
        finally { CultureInfo.CurrentCulture = previous; }
    }

    [TestMethod]
    public async Task MissingRuleShouldStayBlankAndFormulaShouldBeText()
    {
        var uow = new FakeUnitOfWork();
        var alert = CreateAlert();
        alert.ConfidenceScore = null;
        alert.Description = "=1+1";
        uow.Alerts.Add(alert);

        var file = (FileContentResult)await new InferenceResultsController(uow).Export(CancellationToken.None);

        StringAssert.Contains(Read(file), "\"\",\"\",\"\",\"\",\"'=1+1\"");
    }

    private static string Read(FileContentResult file) => Encoding.UTF8.GetString(file.FileContents).TrimStart('\uFEFF');

    private static Alert CreateAlert() => new()
    {
        Id = "A-1", SourceIp = "203.0.113.66", SourcePort = 12345,
        DestinationIp = "192.168.1.10", DestinationPort = 80, Protocol = 6,
        AttackType = "DoS", DetectionSource = DetectionSource.RandomForest, ConfidenceScore = 0.95f
    };
}

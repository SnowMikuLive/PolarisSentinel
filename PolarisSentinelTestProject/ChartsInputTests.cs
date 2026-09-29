using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Application;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Web.Controllers;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class ChartsInputTests
{
    [TestMethod]
    [DataRow("NaN")]
    [DataRow("Infinity")]
    [DataRow("-Infinity")]
    public void CsvShouldRejectNonFiniteNumbers(string value)
    {
        var header = string.Join(",", FlowSnapshot.FeatureNames) + ",label";
        var cells = Enumerable.Repeat("1", 20).ToArray();
        cells[0] = value;

        var valid = CsvFlowParser.TryParse(header + "\n" + string.Join(",", cells) + ",Benign", out var rows, out var error);

        Assert.IsFalse(valid);
        Assert.HasCount(0, rows);
        StringAssert.Contains(error!, "not a valid number");
    }

    [TestMethod]
    [DataRow("999")]
    [DataRow("not-a-model")]
    [DataRow(null)]
    public async Task InvalidModelRequestShouldReturnBadRequest(string? model)
    {
        // 无效请求应在调用模型或数据库之前返回。
        // Invalid input should return before accessing models or the database.
        var controller = new ChartsController(null!, null!, null!, null!, null!);
        var request = model == null ? null : new ModelTestRequest { ModelCombination = model };

        var result = await controller.Test(request, CancellationToken.None);

        Assert.IsInstanceOfType<BadRequestObjectResult>(result);
    }
}

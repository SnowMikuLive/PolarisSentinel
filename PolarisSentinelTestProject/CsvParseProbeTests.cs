using PolarisSentinel.Application;
using PolarisSentinel.Application.Evaluation;

namespace PolarisSentienlUnitTestProject;

[TestClass]
public class CsvParseProbeTests
{
    [TestMethod]
    public void Probe_RealDataset()
    {
        string path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
            "..", "..", "..", "..", "ml", "artifacts", "cic_test_dataset.csv"));
        Console.WriteLine("Path: " + path + " exists=" + File.Exists(path));
        string content = File.ReadAllText(path);
        bool ok = CsvFlowParser.TryParse(content, out var rows, out string? error);
        Console.WriteLine($"OK={ok} rows={rows.Count} error={error}");
        Assert.IsTrue(ok, error);
    }
}

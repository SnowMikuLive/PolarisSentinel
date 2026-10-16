namespace PolarisSentinel.Web.Startup;

internal static class PrerequisiteCheck
{
    private const string NpcapDownload = "https://npcap.com/#download";

    private const string LocalDbDownload =
        "https://download.microsoft.com/download/3/8/d/38de7036-2433-4207-8eae-06e247e17b25/SqlLocalDB.msi";

    private static readonly string[] LocalDbToolsFolders =
    {
        "110", "120", "130", "140", "150", "160", "170"
    };

    public static bool IsSkipped(string[] args)
    {
        if (args.Any(a => string.Equals(a, "--skip-prereq-check", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (string.Equals(Environment.GetEnvironmentVariable("POLARIS_SKIP_PREREQ_CHECK"), "1", StringComparison.Ordinal))
        {
            return true;
        }

        return Environment.CommandLine.Contains("dotnet-ef", StringComparison.OrdinalIgnoreCase);
    }

    public static IReadOnlyList<string> FindMissing(string contentRoot)
    {
        var missing = new List<string>();

        if (!IsNpcapDetected())
        {
            missing.Add(
                "Npcap (the packet capture driver) was not found.\r\n" +
                $"     Download and install it as administrator: {NpcapDownload}");
        }

        if (!IsLocalDbInstalled())
        {
            missing.Add(
                "SQL Server LocalDB was not found.\r\n" +
                $"     Download: {LocalDbDownload}\r\n" +
                "     Install:  msiexec /i SqlLocalDB.msi /qn IACCEPTSQLLOCALDBLICENSETERMS=YES");
        }

        if (!File.Exists(ResolveArtifactPath(contentRoot, null, "rf_model.onnx")))
        {
            missing.Add(
                "The Random Forest model file was not found.\r\n" +
                "     The folder ml\\artifacts must sit next to the executable:\r\n" +
                "     <root>\\PolarisSentinel.Web.exe  and  <root>\\ml\\artifacts\\rf_model.onnx");
        }

        return missing;
    }

    internal static string ResolveArtifactPath(string contentRoot, string? configured, string fileName)
    {
        foreach (string candidate in Candidates(configured, fileName))
        {
            string full = Path.GetFullPath(Path.Combine(contentRoot, candidate));
            if (File.Exists(full))
            {
                return full;
            }
        }

        return Path.GetFullPath(Path.Combine(contentRoot, "ml", "artifacts", fileName));
    }

    private static IEnumerable<string> Candidates(string? configured, string fileName)
    {
        yield return Path.Combine("ml", "artifacts", fileName);

        if (!string.IsNullOrWhiteSpace(configured))
        {
            yield return configured;
        }

        yield return Path.Combine("..", "ml", "artifacts", fileName);
    }

    public static string Describe(IReadOnlyList<string> missing)
    {
        var text = new System.Text.StringBuilder();
        text.AppendLine("Polaris Sentinel cannot start because a required component is missing.");
        text.AppendLine();

        foreach (string item in missing)
        {
            text.AppendLine($"  - {item}");
            text.AppendLine();
        }

        text.AppendLine("Install the missing component(s) and start the application again.");
        text.AppendLine();
        text.AppendLine("To start anyway (for example to open the dashboard only), run the executable with");
        text.AppendLine("the argument --skip-prereq-check.");
        return text.ToString();
    }

    internal static bool IsNpcapDetected()
    {
        string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);

        return File.Exists(Path.Combine(system32, "Npcap", "wpcap.dll"))
            || File.Exists(Path.Combine(system32, "wpcap.dll"))
            || File.Exists(Path.Combine(system32, "Packet.dll"))
            || File.Exists(Path.Combine(system32, "drivers", "npcap.sys"))
            || File.Exists(Path.Combine(system32, "drivers", "npf.sys"))
            || File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Npcap", "NPFInstall.exe"));
    }

    private static bool IsLocalDbInstalled()
    {
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

        foreach (string version in LocalDbToolsFolders)
        {
            if (File.Exists(Path.Combine(programFiles, "Microsoft SQL Server", version, "Tools", "Binn", "SqlLocalDB.exe")))
            {
                return true;
            }
        }

        string? path = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrEmpty(path))
        {
            foreach (string entry in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    if (File.Exists(Path.Combine(entry.Trim('"'), "SqlLocalDB.exe")))
                    {
                        return true;
                    }
                }
                catch (Exception)
                {
                }
            }
        }

        try
        {
            string root = Path.Combine(programFiles, "Microsoft SQL Server");
            return Directory.Exists(root) &&
                Directory.EnumerateFiles(root, "SqlLocalDB.exe", SearchOption.AllDirectories).Any();
        }
        catch (Exception)
        {
            return false;
        }
    }
}

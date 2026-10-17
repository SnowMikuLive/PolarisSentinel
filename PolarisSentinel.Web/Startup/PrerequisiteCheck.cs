namespace PolarisSentinel.Web.Startup;

internal static class PrerequisiteCheck
{
    private const string NpcapDownload = "https://npcap.com/#download";

    internal const string LocalDbDownload =
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

    public static IReadOnlyList<string> FindMissing(string contentRoot, string? connectionString = null)
    {
        var missing = new List<string>();

        if (!IsNpcapDetected())
        {
            missing.Add(
                "Npcap (the packet capture driver) was not found.\r\n" +
                $"     Download and install it as administrator: {NpcapDownload}");
        }

        if (RequiresLocalDb(connectionString) && !IsLocalDbInstalled())
        {
            var message = new System.Text.StringBuilder();
            message.AppendLine("SQL Server LocalDB (SqlLocalDB.exe) was not found.");
            message.AppendLine("     LocalDB is a separate product from SQL Server itself:");
            message.AppendLine("     installing SQL Server Express/Developer/Standard does NOT install LocalDB.");
            message.AppendLine($"     Download: {LocalDbDownload}");
            message.AppendLine("     Install:  msiexec /i SqlLocalDB.msi /qn IACCEPTSQLLOCALDBLICENSETERMS=YES");
            message.AppendLine("     Or let this application do it: PolarisSentinel.Web.exe --install-localdb");

            IReadOnlyList<string> instances = DetectSqlServerInstances();
            if (instances.Count > 0)
            {
                message.AppendLine($"     Detected full SQL Server instance(s): {string.Join(", ", instances)}");
                message.AppendLine("     Either install LocalDB, or point ConnectionStrings:DefaultConnection at an instance, e.g.");
                message.Append(
                    $"     Server={instances[0]};Database=PolarisSentinel;Trusted_Connection=True;" +
                    "TrustServerCertificate=True;MultipleActiveResultSets=True");
            }
            else
            {
                message.Append("     No local SQL Server instance (Express/Developer/Standard) was detected either.");
            }

            missing.Add(message.ToString());
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

    /// <summary>
    /// LocalDB is only a prerequisite when the application is actually configured to use it.
    /// A deployment pointed at a full SQL Server instance (for example "Server=.\SQLEXPRESS")
    /// does not need SqlLocalDB.exe.
    /// </summary>
    internal static bool RequiresLocalDb(string? connectionString)
    {
        // With no explicit connection string the shipped default (appsettings.json) targets LocalDB.
        return string.IsNullOrWhiteSpace(connectionString)
            || connectionString.Contains("(localdb)", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Finds the full SQL Server instances (Express/Developer/Standard/Enterprise) installed on this
    /// machine, reported as the names a connection string would use (".\SQLEXPRESS" or "." for a
    /// default instance). LocalDB is a different product and never registers here, so an empty result
    /// means "no full instance", not "no SQL Server at all".
    /// </summary>
    internal static IReadOnlyList<string> DetectSqlServerInstances()
    {
        var instances = new List<string>();

        foreach (Environment.SpecialFolder folder in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
        {
            try
            {
                string root = Path.Combine(Environment.GetFolderPath(folder), "Microsoft SQL Server");
                if (!Directory.Exists(root))
                {
                    continue;
                }

                // A full instance is laid out as "<root>\<id>.<instance>" (for example MSSQL17.SQLEXPRESS).
                foreach (string directory in Directory.EnumerateDirectories(root, "MSSQL*"))
                {
                    string folderName = Path.GetFileName(directory);
                    int separator = folderName.IndexOf('.');

                    if (separator < 0 || separator == folderName.Length - 1)
                    {
                        continue;
                    }

                    string instance = folderName[(separator + 1)..];
                    instances.Add(string.Equals(instance, "MSSQLSERVER", StringComparison.OrdinalIgnoreCase)
                        ? "."
                        : $@".\{instance}");
                }
            }
            catch (Exception)
            {
                // Best effort only: this feeds a diagnostic message, never a decision.
            }
        }

        return instances.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
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

    internal static bool IsLocalDbInstalled() => FindSqlLocalDbExecutable() is not null;

    /// <summary>Full path of SqlLocalDB.exe when LocalDB is installed, otherwise null.</summary>
    internal static string? FindSqlLocalDbExecutable()
    {
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

        foreach (string version in LocalDbToolsFolders)
        {
            string candidate = Path.Combine(programFiles, "Microsoft SQL Server", version, "Tools", "Binn", "SqlLocalDB.exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        string? path = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrEmpty(path))
        {
            foreach (string entry in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    string candidate = Path.Combine(entry.Trim('"'), "SqlLocalDB.exe");
                    if (File.Exists(candidate))
                    {
                        return candidate;
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
            if (Directory.Exists(root))
            {
                return Directory.EnumerateFiles(root, "SqlLocalDB.exe", SearchOption.AllDirectories).FirstOrDefault();
            }
        }
        catch (Exception)
        {
        }

        return null;
    }
}

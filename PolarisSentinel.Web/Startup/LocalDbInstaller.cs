using System.Diagnostics;
using System.Net.Http;

namespace PolarisSentinel.Web.Startup;

/// <summary>
/// Bootstraps SQL Server LocalDB on a machine that has no local database yet: downloads the official
/// SqlLocalDB.msi from Microsoft and installs it silently, then makes sure the default instance exists.
///
/// This runs during start-up, before the host (and therefore the file logger) exists, so progress is
/// reported through the supplied callback and the message boxes of <see cref="StartupSupport"/>.
/// It never installs anything without consent: the user is asked first unless the unattended switch
/// <c>--install-localdb</c> / <c>POLARIS_AUTO_INSTALL_LOCALDB=1</c> is used, and an opt-out exists via
/// <c>--no-localdb-install</c> / <c>POLARIS_NO_LOCALDB_INSTALL=1</c>.
/// </summary>
internal static class LocalDbInstaller
{
    private const string OptOutVariable = "POLARIS_NO_LOCALDB_INSTALL";
    private const string UnattendedVariable = "POLARIS_AUTO_INSTALL_LOCALDB";
    private const string InstallSwitch = "--install-localdb";
    private const string OptOutSwitch = "--no-localdb-install";

    private const string LicenseArgument = "IACCEPTSQLLOCALDBLICENSETERMS=YES";
    private const string DefaultInstanceName = "MSSQLLocalDB";

    /// <summary>False when the operator disabled automatic installation of LocalDB.</summary>
    public static bool IsEnabled(string[] args)
        => !args.Any(a => string.Equals(a, OptOutSwitch, StringComparison.OrdinalIgnoreCase))
           && !string.Equals(Environment.GetEnvironmentVariable(OptOutVariable), "1", StringComparison.Ordinal);

    /// <summary>True when the user asked for an unattended install (no confirmation dialog).</summary>
    public static bool IsUnattended(string[] args)
        => args.Any(a => string.Equals(a, InstallSwitch, StringComparison.OrdinalIgnoreCase))
           || string.Equals(Environment.GetEnvironmentVariable(UnattendedVariable), "1", StringComparison.Ordinal);

    public static string Explain() =>
        "SQL Server LocalDB is not installed on this computer, and no other local SQL Server instance " +
        "was detected." + Environment.NewLine + Environment.NewLine +
        "This application needs a local database. Download and install SQL Server LocalDB now?" + Environment.NewLine +
        Environment.NewLine +
        "  - about 61 MB, downloaded from download.microsoft.com" + Environment.NewLine +
        "  - installs silently with administrator rights" + Environment.NewLine +
        "  - takes a few minutes" + Environment.NewLine + Environment.NewLine +
        "Choose No to install it yourself later.";

    /// <summary>
    /// Downloads and installs LocalDB, then guarantees the default instance exists.
    /// Returns true when LocalDB is installed at the end.
    /// </summary>
    public static async Task<bool> InstallAsync(Action<string> log)
    {
        if (PrerequisiteCheck.IsLocalDbInstalled())
        {
            return true;
        }

        if (!StartupSupport.IsAdministrator())
        {
            log("SQL Server LocalDB cannot be installed automatically: administrator rights are required.");
            return false;
        }

        string installerPath = Path.Combine(Path.GetTempPath(), $"SqlLocalDB-{Guid.NewGuid():N}.msi");

        try
        {
            log("Downloading SQL Server LocalDB (about 61 MB) ...");

            using (var http = new HttpClient { Timeout = TimeSpan.FromMinutes(15) })
            {
                using HttpResponseMessage response = await http.GetAsync(
                    PrerequisiteCheck.LocalDbDownload,
                    HttpCompletionOption.ResponseHeadersRead);

                response.EnsureSuccessStatusCode();

                await using FileStream file = File.Create(installerPath);
                await response.Content.CopyToAsync(file);
            }

            log("Installing SQL Server LocalDB silently ...");

            // 0 = success, 3010 = success but a restart is pending.
            int exitCode = await RunAsync("msiexec.exe", $"/i \"{installerPath}\" /qn {LicenseArgument} /norestart");
            if (exitCode is not (0 or 3010))
            {
                log($"The SQL Server LocalDB installer returned exit code {exitCode}.");
                return false;
            }

            EnsureDefaultInstance(log);

            bool installed = PrerequisiteCheck.IsLocalDbInstalled();
            log(installed
                ? "SQL Server LocalDB is installed."
                : "The SQL Server LocalDB installer finished but LocalDB is still not detected.");

            return installed;
        }
        catch (Exception ex)
        {
            log($"SQL Server LocalDB could not be installed: {ex.Message}");
            return false;
        }
        finally
        {
            try
            {
                File.Delete(installerPath);
            }
            catch (Exception)
            {
                // Leaving a temporary file behind is not worth failing the start-up for.
            }
        }
    }

    /// <summary>
    /// LocalDB normally creates MSSQLLocalDB on first use; creating and starting it explicitly removes
    /// any doubt and costs nothing when it already exists.
    /// </summary>
    private static void EnsureDefaultInstance(Action<string> log)
    {
        string? sqlLocalDb = PrerequisiteCheck.FindSqlLocalDbExecutable();
        if (sqlLocalDb is null)
        {
            return;
        }

        Run(sqlLocalDb, $"create {DefaultInstanceName}");
        Run(sqlLocalDb, $"start {DefaultInstanceName}");
    }

    private static void Run(string fileName, string arguments) => RunAsync(fileName, arguments).GetAwaiter().GetResult();

    private static async Task<int> RunAsync(string fileName, string arguments)
    {
        try
        {
            var startInfo = new ProcessStartInfo(fileName, arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };

            using Process? process = Process.Start(startInfo);
            if (process is null)
            {
                return -1;
            }

            Task<string> standardOutput = process.StandardOutput.ReadToEndAsync();
            Task<string> standardError = process.StandardError.ReadToEndAsync();

            await process.WaitForExitAsync();

            // Drain the pipes so the process can never block on a full buffer.
            await Task.WhenAll(standardOutput, standardError);

            return process.ExitCode;
        }
        catch (Exception)
        {
            return -1;
        }
    }
}

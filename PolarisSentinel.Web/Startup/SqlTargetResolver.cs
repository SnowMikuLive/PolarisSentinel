using Microsoft.Data.SqlClient;

namespace PolarisSentinel.Web.Startup;

/// <summary>
/// Decides which SQL Server the application actually talks to.
///
/// The shipped default connection string targets SQL Server LocalDB. When the configuration asks for
/// LocalDB but LocalDB is not installed on the machine - the normal outcome of a plain "SQL Server
/// Express/Developer" install, which does not include LocalDB - the detected local instance is used
/// instead, so double-clicking the executable works without editing any file. The database itself is
/// still created by the migrations on first start.
///
/// An explicitly configured, parseable, non-LocalDB target is never rewritten: that is an
/// administrator's decision, and a typo in it should surface as a database error rather than be
/// silently replaced by something else.
/// </summary>
internal static class SqlTargetResolver
{
    private const string DefaultLocalDbConnection =
        @"Server=(localdb)\MSSQLLocalDB;Database=PolarisSentinel;Trusted_Connection=True;MultipleActiveResultSets=true";

    private const string FallbackDatabaseName = "PolarisSentinel";

    public static string Resolve(string? configured)
    {
        string? dataSource = ParsedDataSource(configured);

        // 1. Explicit, valid, non-LocalDB target: use it verbatim.
        if (dataSource is not null && !IsLocalDb(dataSource))
        {
            return configured!;
        }

        // 2. LocalDB is what is wanted (or the value is unusable) and LocalDB is available.
        if (PrerequisiteCheck.IsLocalDbInstalled())
        {
            return dataSource is null ? DefaultLocalDbConnection : configured!;
        }

        // 3. LocalDB is unavailable: fall back to a full instance if one is installed.
        IReadOnlyList<string> instances = PrerequisiteCheck.DetectSqlServerInstances();
        string? instance = instances.Count > 0 ? instances[0] : null;
        if (instance is not null)
        {
            return $"Server={instance};Database={DatabaseName(configured)};" +
                   "Trusted_Connection=True;TrustServerCertificate=True;MultipleActiveResultSets=True";
        }

        // 4. Nothing usable: keep the LocalDB default so the prerequisite check explains what to install.
        return DefaultLocalDbConnection;
    }

    /// <summary>Renders a connection string for the log without leaking a password.</summary>
    public static string Describe(string? connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return "(not configured)";
        }

        try
        {
            var builder = new SqlConnectionStringBuilder(connectionString);

            string authentication = string.IsNullOrEmpty(builder.UserID)
                ? "Windows authentication"
                : $"SQL login '{builder.UserID}'";

            return $"{builder.DataSource}/{builder.InitialCatalog} ({authentication})";
        }
        catch (ArgumentException)
        {
            return "(unusable connection string)";
        }
    }

    private static bool IsLocalDb(string dataSource)
        => dataSource.Contains("(localdb)", StringComparison.OrdinalIgnoreCase);

    /// <summary>Data source of a usable connection string, or null when it is empty or malformed.</summary>
    private static string? ParsedDataSource(string? connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return null;
        }

        try
        {
            string dataSource = new SqlConnectionStringBuilder(connectionString).DataSource;

            return string.IsNullOrWhiteSpace(dataSource) ? null : dataSource;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static string DatabaseName(string? connectionString)
    {
        try
        {
            string catalog = string.IsNullOrWhiteSpace(connectionString)
                ? string.Empty
                : new SqlConnectionStringBuilder(connectionString).InitialCatalog;

            return string.IsNullOrWhiteSpace(catalog) ? FallbackDatabaseName : catalog;
        }
        catch (ArgumentException)
        {
            return FallbackDatabaseName;
        }
    }
}

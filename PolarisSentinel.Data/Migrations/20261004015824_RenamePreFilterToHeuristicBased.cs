using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PolarisSentinel.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class RenamePreFilterToHeuristicBased : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Rename every existing DetectionSource value before the seed rows are
            // touched, so pre-existing alerts and policies keep mapping to the enum.
            migrationBuilder.Sql(
                "UPDATE [Alerts] SET [DetectionSource] = 'HeuristicBased' WHERE [DetectionSource] = 'PreFilter';");
            migrationBuilder.Sql(
                "UPDATE [Policies] SET [DetectionSource] = 'HeuristicBased' WHERE [DetectionSource] = 'PreFilter';");

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-1",
                columns: new[] { "DetectionSource", "Name" },
                values: new object[] { "HeuristicBased", "Heuristic DoS" });

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-4",
                columns: new[] { "DetectionSource", "Name" },
                values: new object[] { "HeuristicBased", "Heuristic PortScan" });

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-5",
                columns: new[] { "DetectionSource", "Name" },
                values: new object[] { "HeuristicBased", "Heuristic BruteForce" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-1",
                columns: new[] { "DetectionSource", "Name" },
                values: new object[] { "PreFilter", "Prefilter DoS" });

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-4",
                columns: new[] { "DetectionSource", "Name" },
                values: new object[] { "PreFilter", "Prefilter PortScan" });

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-5",
                columns: new[] { "DetectionSource", "Name" },
                values: new object[] { "PreFilter", "Prefilter BruteForce" });

            migrationBuilder.Sql(
                "UPDATE [Alerts] SET [DetectionSource] = 'PreFilter' WHERE [DetectionSource] = 'HeuristicBased';");
            migrationBuilder.Sql(
                "UPDATE [Policies] SET [DetectionSource] = 'PreFilter' WHERE [DetectionSource] = 'HeuristicBased';");
        }
    }
}

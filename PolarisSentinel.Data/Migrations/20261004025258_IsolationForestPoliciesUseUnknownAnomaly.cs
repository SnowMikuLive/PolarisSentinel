using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PolarisSentinel.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class IsolationForestPoliciesUseUnknownAnomaly : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // The Isolation Forest only reports unnamed anomalies, so any existing
            // policy that targets it must use Unknown_Anomaly to ever match.
            migrationBuilder.Sql(
                "UPDATE [Policies] SET [AttackType] = 'Unknown_Anomaly' WHERE [DetectionSource] = 'IsolationForest' AND [AttackType] <> 'Unknown_Anomaly';");

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-6",
                column: "AttackType",
                value: "Unknown_Anomaly");

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-7",
                column: "AttackType",
                value: "Unknown_Anomaly");

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-8",
                column: "AttackType",
                value: "Unknown_Anomaly");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-6",
                column: "AttackType",
                value: "DoS");

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-7",
                column: "AttackType",
                value: "PortScan");

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-8",
                column: "AttackType",
                value: "BruteForce");
        }
    }
}

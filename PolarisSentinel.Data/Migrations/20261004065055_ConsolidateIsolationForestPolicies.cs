using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace PolarisSentinel.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class ConsolidateIsolationForestPolicies : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-8");

            migrationBuilder.DeleteData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-9");

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-6",
                columns: new[] { "Description", "IfThreshold", "Name", "Priority" },
                values: new object[] { "Block the source of an Isolation Forest abnormal behavior.", 0.7f, "Isolation Forest abnormal", 90 });

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-7",
                columns: new[] { "AttackType", "Description", "DetectionSource", "IfThreshold", "Name", "Priority", "RfThreshold" },
                values: new object[] { "DoS", "Block the source of a Random Forest DoS detection.", "RandomForest", null, "Random Forest DoS", 90, 0.7f });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-6",
                columns: new[] { "Description", "IfThreshold", "Name", "Priority" },
                values: new object[] { "Block the source of an Isolation Forest DoS anomaly.", 0.6f, "Isolation Forest DoS", 80 });

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-7",
                columns: new[] { "AttackType", "Description", "DetectionSource", "IfThreshold", "Name", "Priority", "RfThreshold" },
                values: new object[] { "Unknown_Anomaly", "Block the source of an Isolation Forest port scan anomaly.", "IsolationForest", 0.6f, "Isolation Forest PortScan", 80, null });

            migrationBuilder.InsertData(
                table: "Policies",
                columns: new[] { "Id", "Action", "AttackType", "BlockDurationMinutes", "CreatedAt", "Description", "DetectionSource", "IfThreshold", "IsEnabled", "Name", "Priority", "RfThreshold", "UpdatedAt", "UserId" },
                values: new object[,]
                {
                    { "P-8", "BlockInboundIp", "Unknown_Anomaly", 60, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "Block the source of an Isolation Forest brute force anomaly.", "IsolationForest", 0.6f, true, "Isolation Forest BruteForce", 80, null, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "admin" },
                    { "P-9", "BlockInboundIp", "DoS", 60, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "Block the source of a Random Forest DoS detection.", "RandomForest", null, true, "Random Forest DoS", 90, 0.7f, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "admin" }
                });
        }
    }
}

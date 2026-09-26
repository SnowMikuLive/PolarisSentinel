using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace PolarisSentinel.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class AddAttackDetectionPolicies : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "Policies",
                columns: new[] { "Id", "Action", "AttackType", "BlockDurationMinutes", "CreatedAt", "Description", "DetectionSource", "IfThreshold", "IsEnabled", "Name", "Priority", "RfThreshold", "UpdatedAt", "UserId" },
                values: new object[,]
                {
                    { "P-4", "BlockInboundIp", "PortScan", 60, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "Block the source of any rule-based port scan detection.", "PreFilter", null, true, "Prefilter PortScan", 100, null, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "admin" },
                    { "P-5", "BlockInboundIp", "BruteForce", 60, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "Block the source of any rule-based brute force detection.", "PreFilter", null, true, "Prefilter BruteForce", 100, null, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "admin" },
                    { "P-6", "BlockInboundIp", "DoS", 60, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "Block the source of an Isolation Forest DoS anomaly.", "IsolationForest", 0.6f, true, "Isolation Forest DoS", 80, null, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "admin" },
                    { "P-7", "BlockInboundIp", "PortScan", 60, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "Block the source of an Isolation Forest port scan anomaly.", "IsolationForest", 0.6f, true, "Isolation Forest PortScan", 80, null, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "admin" },
                    { "P-8", "BlockInboundIp", "BruteForce", 60, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "Block the source of an Isolation Forest brute force anomaly.", "IsolationForest", 0.6f, true, "Isolation Forest BruteForce", 80, null, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "admin" },
                    { "P-9", "BlockInboundIp", "DoS", 60, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "Block the source of a Random Forest DoS detection.", "RandomForest", null, true, "Random Forest DoS", 90, 0.7f, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-4");

            migrationBuilder.DeleteData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-5");

            migrationBuilder.DeleteData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-6");

            migrationBuilder.DeleteData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-7");

            migrationBuilder.DeleteData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-8");

            migrationBuilder.DeleteData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-9");
        }
    }
}

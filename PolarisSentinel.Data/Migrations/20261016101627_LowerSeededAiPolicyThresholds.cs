using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PolarisSentinel.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class LowerSeededAiPolicyThresholds : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-2",
                column: "RfThreshold",
                value: 0.5f);

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-3",
                column: "RfThreshold",
                value: 0.5f);

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-6",
                column: "IfThreshold",
                value: 0.5f);

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-7",
                column: "RfThreshold",
                value: 0.5f);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-2",
                column: "RfThreshold",
                value: 0.7f);

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-3",
                column: "RfThreshold",
                value: 0.7f);

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-6",
                column: "IfThreshold",
                value: 0.7f);

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-7",
                column: "RfThreshold",
                value: 0.7f);
        }
    }
}

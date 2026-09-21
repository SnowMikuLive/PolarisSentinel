using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace PolarisSentinel.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class RemoveAllowlistAndCooldown : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Allowlist",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "DecisionCooldownSeconds",
                table: "Policies");

            migrationBuilder.AlterColumn<int>(
                name: "SourcePort",
                table: "Rules",
                type: "int",
                nullable: true,
                oldClrType: typeof(int),
                oldType: "int");

            migrationBuilder.AlterColumn<string>(
                name: "SourceIp",
                table: "Rules",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(64)",
                oldMaxLength: 64);

            migrationBuilder.AlterColumn<byte>(
                name: "Protocol",
                table: "Rules",
                type: "tinyint",
                nullable: true,
                oldClrType: typeof(byte),
                oldType: "tinyint");

            migrationBuilder.AlterColumn<int>(
                name: "DestinationPort",
                table: "Rules",
                type: "int",
                nullable: true,
                oldClrType: typeof(int),
                oldType: "int");

            migrationBuilder.AlterColumn<string>(
                name: "DestinationIp",
                table: "Rules",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(64)",
                oldMaxLength: 64);

            migrationBuilder.InsertData(
                table: "Policies",
                columns: new[] { "Id", "BlockDurationMinutes", "CreatedAt", "DetectionSource", "IfConfidenceThreshold", "MatchAttackTypes", "MatchProtocol", "RfConfidenceThreshold", "RuleDestinationIpAction", "RuleDestinationPortAction", "RuleSourceIpAction", "RuleSourcePortAction", "UpdatedAt", "UserId" },
                values: new object[,]
                {
                    { "P-1", 10, new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "PreFilter", null, null, (byte)0, null, "Allow", "Allow", "Block", "Allow", new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "admin" },
                    { "P-2", 10, new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "PreFilter", null, "DoS", (byte)0, null, "Allow", "Allow", "Block", "Block", new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "admin" },
                    { "P-3", 10, new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "PreFilter", null, "DoS", (byte)1, null, "Allow", "Allow", "Block", "Allow", new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "admin" },
                    { "P-4", 10, new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "PreFilter", null, "DoS", (byte)17, null, "Allow", "Allow", "Block", "Allow", new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "admin" },
                    { "P-5", 10, new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "RandomForest", null, null, (byte)0, 0.6f, "Allow", "Allow", "Block", "Allow", new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-1");

            migrationBuilder.DeleteData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-2");

            migrationBuilder.DeleteData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-3");

            migrationBuilder.DeleteData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-4");

            migrationBuilder.DeleteData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-5");

            migrationBuilder.AlterColumn<int>(
                name: "SourcePort",
                table: "Rules",
                type: "int",
                nullable: false,
                defaultValue: 0,
                oldClrType: typeof(int),
                oldType: "int",
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "SourceIp",
                table: "Rules",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "nvarchar(64)",
                oldMaxLength: 64,
                oldNullable: true);

            migrationBuilder.AlterColumn<byte>(
                name: "Protocol",
                table: "Rules",
                type: "tinyint",
                nullable: false,
                defaultValue: (byte)0,
                oldClrType: typeof(byte),
                oldType: "tinyint",
                oldNullable: true);

            migrationBuilder.AlterColumn<int>(
                name: "DestinationPort",
                table: "Rules",
                type: "int",
                nullable: false,
                defaultValue: 0,
                oldClrType: typeof(int),
                oldType: "int",
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "DestinationIp",
                table: "Rules",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "nvarchar(64)",
                oldMaxLength: 64,
                oldNullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Allowlist",
                table: "Policies",
                type: "nvarchar(1024)",
                maxLength: 1024,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<int>(
                name: "DecisionCooldownSeconds",
                table: "Policies",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }
    }
}

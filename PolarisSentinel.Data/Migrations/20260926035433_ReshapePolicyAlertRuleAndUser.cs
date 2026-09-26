using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace PolarisSentinel.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class ReshapePolicyAlertRuleAndUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-4");

            migrationBuilder.DeleteData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-5");

            migrationBuilder.DropColumn(
                name: "AttackType",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "Enabled",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "IsBlockRule",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "MatchProtocol",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "RuleDestinationIpAction",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "RuleDestinationPortAction",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "RuleSourceIpAction",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "RuleSourcePortAction",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "Action",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "Confidence",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "DecidedAt",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "Reason",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "RuleName",
                table: "Alerts");

            migrationBuilder.RenameColumn(
                name: "RfConfidenceThreshold",
                table: "Policies",
                newName: "RfThreshold");

            migrationBuilder.RenameColumn(
                name: "MatchAttackTypes",
                table: "Policies",
                newName: "Description");

            migrationBuilder.RenameColumn(
                name: "IfConfidenceThreshold",
                table: "Policies",
                newName: "IfThreshold");

            migrationBuilder.RenameColumn(
                name: "Source",
                table: "Alerts",
                newName: "DetectionSource");

            migrationBuilder.RenameColumn(
                name: "DetectedAt",
                table: "Alerts",
                newName: "CreatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_Alerts_DetectedAt",
                table: "Alerts",
                newName: "IX_Alerts_CreatedAt");

            migrationBuilder.AlterColumn<string>(
                name: "Status",
                table: "Rules",
                type: "nvarchar(16)",
                maxLength: 16,
                nullable: false,
                oldClrType: typeof(int),
                oldType: "int");

            migrationBuilder.AlterColumn<string>(
                name: "Action",
                table: "Rules",
                type: "nvarchar(32)",
                maxLength: 32,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(16)",
                oldMaxLength: 16);

            migrationBuilder.AlterColumn<string>(
                name: "DetectionSource",
                table: "Policies",
                type: "nvarchar(32)",
                maxLength: 32,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(32)",
                oldMaxLength: 32);

            migrationBuilder.AddColumn<string>(
                name: "Action",
                table: "Policies",
                type: "nvarchar(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "AttackType",
                table: "Policies",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsEnabled",
                table: "Policies",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "Name",
                table: "Policies",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<int>(
                name: "Priority",
                table: "Policies",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<bool>(
                name: "MustChangePassword",
                table: "AspNetUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "AckCount",
                table: "Alerts",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<float>(
                name: "ConfidenceScore",
                table: "Alerts",
                type: "real",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Description",
                table: "Alerts",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "FinCount",
                table: "Alerts",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "FlowSnapshotJson",
                table: "Alerts",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "PshCount",
                table: "Alerts",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "RstCount",
                table: "Alerts",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "SynCount",
                table: "Alerts",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-1",
                columns: new[] { "Action", "AttackType", "BlockDurationMinutes", "CreatedAt", "Description", "IsEnabled", "Name", "Priority", "UpdatedAt" },
                values: new object[] { "BlockInboundIp", "DoS", 60, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "Block the source of any rule-based DoS detection.", true, "Prefilter DoS", 100, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified) });

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-2",
                columns: new[] { "Action", "AttackType", "BlockDurationMinutes", "CreatedAt", "Description", "DetectionSource", "IsEnabled", "Name", "Priority", "RfThreshold", "UpdatedAt" },
                values: new object[] { "BlockInboundIp", "PortScan", 60, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "Block the source of a Random Forest port scan detection.", "RandomForest", true, "Random Forest PortScan", 90, 0.7f, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified) });

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-3",
                columns: new[] { "Action", "AttackType", "BlockDurationMinutes", "CreatedAt", "Description", "DetectionSource", "IsEnabled", "Name", "Priority", "RfThreshold", "UpdatedAt" },
                values: new object[] { "BlockInboundIp", "BruteForce", 60, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified), "Block the source of a Random Forest brute force detection.", "RandomForest", true, "Random Forest BruteForce", 90, 0.7f, new DateTime(2026, 9, 26, 0, 0, 0, 0, DateTimeKind.Unspecified) });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Action",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "AttackType",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "IsEnabled",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "Name",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "Priority",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "MustChangePassword",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "AckCount",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "ConfidenceScore",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "Description",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "FinCount",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "FlowSnapshotJson",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "PshCount",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "RstCount",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "SynCount",
                table: "Alerts");

            migrationBuilder.RenameColumn(
                name: "RfThreshold",
                table: "Policies",
                newName: "RfConfidenceThreshold");

            migrationBuilder.RenameColumn(
                name: "IfThreshold",
                table: "Policies",
                newName: "IfConfidenceThreshold");

            migrationBuilder.RenameColumn(
                name: "Description",
                table: "Policies",
                newName: "MatchAttackTypes");

            migrationBuilder.RenameColumn(
                name: "DetectionSource",
                table: "Alerts",
                newName: "Source");

            migrationBuilder.RenameColumn(
                name: "CreatedAt",
                table: "Alerts",
                newName: "DetectedAt");

            migrationBuilder.RenameIndex(
                name: "IX_Alerts_CreatedAt",
                table: "Alerts",
                newName: "IX_Alerts_DetectedAt");

            migrationBuilder.AlterColumn<int>(
                name: "Status",
                table: "Rules",
                type: "int",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(16)",
                oldMaxLength: 16);

            migrationBuilder.AlterColumn<string>(
                name: "Action",
                table: "Rules",
                type: "nvarchar(16)",
                maxLength: 16,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(32)",
                oldMaxLength: 32);

            migrationBuilder.AddColumn<string>(
                name: "AttackType",
                table: "Rules",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "Enabled",
                table: "Rules",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "IsBlockRule",
                table: "Rules",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AlterColumn<string>(
                name: "DetectionSource",
                table: "Policies",
                type: "nvarchar(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "nvarchar(32)",
                oldMaxLength: 32,
                oldNullable: true);

            migrationBuilder.AddColumn<byte>(
                name: "MatchProtocol",
                table: "Policies",
                type: "tinyint",
                nullable: false,
                defaultValue: (byte)0);

            migrationBuilder.AddColumn<string>(
                name: "RuleDestinationIpAction",
                table: "Policies",
                type: "nvarchar(16)",
                maxLength: 16,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "RuleDestinationPortAction",
                table: "Policies",
                type: "nvarchar(16)",
                maxLength: 16,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "RuleSourceIpAction",
                table: "Policies",
                type: "nvarchar(16)",
                maxLength: 16,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "RuleSourcePortAction",
                table: "Policies",
                type: "nvarchar(16)",
                maxLength: 16,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Action",
                table: "Alerts",
                type: "nvarchar(16)",
                maxLength: 16,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<float>(
                name: "Confidence",
                table: "Alerts",
                type: "real",
                nullable: false,
                defaultValue: 0f);

            migrationBuilder.AddColumn<DateTime>(
                name: "DecidedAt",
                table: "Alerts",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<string>(
                name: "Reason",
                table: "Alerts",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "RuleName",
                table: "Alerts",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-1",
                columns: new[] { "BlockDurationMinutes", "CreatedAt", "MatchAttackTypes", "MatchProtocol", "RuleDestinationIpAction", "RuleDestinationPortAction", "RuleSourceIpAction", "RuleSourcePortAction", "UpdatedAt" },
                values: new object[] { 10, new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), null, (byte)0, "Allow", "Allow", "Block", "Allow", new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified) });

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-2",
                columns: new[] { "BlockDurationMinutes", "CreatedAt", "DetectionSource", "MatchAttackTypes", "MatchProtocol", "RfConfidenceThreshold", "RuleDestinationIpAction", "RuleDestinationPortAction", "RuleSourceIpAction", "RuleSourcePortAction", "UpdatedAt" },
                values: new object[] { 10, new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "PreFilter", "DoS", (byte)0, null, "Allow", "Allow", "Block", "Block", new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified) });

            migrationBuilder.UpdateData(
                table: "Policies",
                keyColumn: "Id",
                keyValue: "P-3",
                columns: new[] { "BlockDurationMinutes", "CreatedAt", "DetectionSource", "MatchAttackTypes", "MatchProtocol", "RfConfidenceThreshold", "RuleDestinationIpAction", "RuleDestinationPortAction", "RuleSourceIpAction", "RuleSourcePortAction", "UpdatedAt" },
                values: new object[] { 10, new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "PreFilter", "DoS", (byte)1, null, "Allow", "Allow", "Block", "Allow", new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified) });

            migrationBuilder.InsertData(
                table: "Policies",
                columns: new[] { "Id", "BlockDurationMinutes", "CreatedAt", "DetectionSource", "IfConfidenceThreshold", "MatchAttackTypes", "MatchProtocol", "RfConfidenceThreshold", "RuleDestinationIpAction", "RuleDestinationPortAction", "RuleSourceIpAction", "RuleSourcePortAction", "UpdatedAt", "UserId" },
                values: new object[,]
                {
                    { "P-4", 10, new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "PreFilter", null, "DoS", (byte)17, null, "Allow", "Allow", "Block", "Allow", new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "admin" },
                    { "P-5", 10, new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "RandomForest", null, null, (byte)0, 0.6f, "Allow", "Allow", "Block", "Allow", new DateTime(2026, 9, 21, 0, 0, 0, 0, DateTimeKind.Unspecified), "admin" }
                });
        }
    }
}

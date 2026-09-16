using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace PolarisSentinel.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Alerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SourceIp = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: false),
                    SourcePort = table.Column<int>(type: "int", nullable: false),
                    DestinationIp = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: false),
                    DestinationPort = table.Column<int>(type: "int", nullable: false),
                    Protocol = table.Column<byte>(type: "tinyint", nullable: false),
                    AttackType = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Confidence = table.Column<float>(type: "real", nullable: false),
                    Severity = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: true),
                    Source = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    DetectedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Alerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Policies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    UserId = table.Column<string>(type: "nvarchar(450)", maxLength: 450, nullable: false),
                    Action = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    RfConfidenceThreshold = table.Column<float>(type: "real", nullable: false),
                    AutoBlockConfidenceThreshold = table.Column<float>(type: "real", nullable: false),
                    BlockDurationMinutes = table.Column<int>(type: "int", nullable: false),
                    DecisionCooldownSeconds = table.Column<int>(type: "int", nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Policies", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Rules",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PolicyId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    AlertId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Action = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    RemoteAddress = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: false),
                    Status = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Rules", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Rules_Alerts_AlertId",
                        column: x => x.AlertId,
                        principalTable: "Alerts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_Rules_Policies_PolicyId",
                        column: x => x.PolicyId,
                        principalTable: "Policies",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.InsertData(
                table: "Policies",
                columns: new[] { "Id", "Action", "AutoBlockConfidenceThreshold", "BlockDurationMinutes", "CreatedAt", "DecisionCooldownSeconds", "IsActive", "Name", "RfConfidenceThreshold", "UserId" },
                values: new object[,]
                {
                    { new Guid("11111111-1111-1111-1111-111111111111"), "Monitor", 0.8f, 60, new DateTime(2026, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 60, true, "Default Monitor", 0.6f, "" },
                    { new Guid("22222222-2222-2222-2222-222222222222"), "Block", 0.9f, 120, new DateTime(2026, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 30, true, "Default Block", 0.7f, "" }
                });

            migrationBuilder.CreateIndex(
                name: "IX_Alerts_DetectedAt",
                table: "Alerts",
                column: "DetectedAt");

            migrationBuilder.CreateIndex(
                name: "IX_Alerts_SourceIp",
                table: "Alerts",
                column: "SourceIp");

            migrationBuilder.CreateIndex(
                name: "IX_Rules_AlertId",
                table: "Rules",
                column: "AlertId");

            migrationBuilder.CreateIndex(
                name: "IX_Rules_PolicyId",
                table: "Rules",
                column: "PolicyId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Rules");

            migrationBuilder.DropTable(
                name: "Alerts");

            migrationBuilder.DropTable(
                name: "Policies");
        }
    }
}

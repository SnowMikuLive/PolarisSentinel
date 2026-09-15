using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PolarisSentinel.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddUsersPoliciesAlertsRules : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DetectionEvents");

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
                    Source = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    DetectedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Alerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    Email = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Phone = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: true),
                    PasswordHash = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Policies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
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
                    table.ForeignKey(
                        name: "FK_Policies_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Rules",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PolicyId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AlertId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Action = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    RemoteAddress = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: false),
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
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_Rules_Policies_PolicyId",
                        column: x => x.PolicyId,
                        principalTable: "Policies",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
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
                name: "IX_Policies_UserId",
                table: "Policies",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_Rules_AlertId",
                table: "Rules",
                column: "AlertId");

            migrationBuilder.CreateIndex(
                name: "IX_Rules_PolicyId",
                table: "Rules",
                column: "PolicyId");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Email",
                table: "Users",
                column: "Email",
                unique: true);
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

            migrationBuilder.DropTable(
                name: "Users");

            migrationBuilder.CreateTable(
                name: "DetectionEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Action = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    AttackType = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Confidence = table.Column<float>(type: "real", nullable: false),
                    DecidedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    DestinationIp = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: false),
                    DestinationPort = table.Column<int>(type: "int", nullable: false),
                    Reason = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    RuleName = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                    Source = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    SourceIp = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DetectionEvents", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DetectionEvents_DecidedAt",
                table: "DetectionEvents",
                column: "DecidedAt");

            migrationBuilder.CreateIndex(
                name: "IX_DetectionEvents_SourceIp",
                table: "DetectionEvents",
                column: "SourceIp");
        }
    }
}

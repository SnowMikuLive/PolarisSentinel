using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PolarisSentinel.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialDetections : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DetectionEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SourceIp = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: false),
                    DestinationIp = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: false),
                    DestinationPort = table.Column<int>(type: "int", nullable: false),
                    AttackType = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Confidence = table.Column<float>(type: "real", nullable: false),
                    Source = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    RuleName = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                    Action = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    Reason = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    DecidedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
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

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DetectionEvents");
        }
    }
}

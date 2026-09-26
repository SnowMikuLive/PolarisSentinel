using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PolarisSentinel.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class AddTrafficRecords : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "TrafficRecords",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    AlertId = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    SourceIp = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: false),
                    DestinationIp = table.Column<string>(type: "nvarchar(45)", maxLength: 45, nullable: false),
                    DestinationPort = table.Column<int>(type: "int", nullable: false),
                    AttackType = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    ConfidenceScore = table.Column<float>(type: "real", nullable: true),
                    Action = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    Reason = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Source = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    RuleName = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true),
                    Verdict = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TrafficRecords", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TrafficRecords_CreatedAt",
                table: "TrafficRecords",
                column: "CreatedAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "TrafficRecords");
        }
    }
}

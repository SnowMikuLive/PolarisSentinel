using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PolarisSentinel.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddAlertDecisionFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Action",
                table: "Alerts",
                type: "nvarchar(16)",
                maxLength: 16,
                nullable: false,
                defaultValue: "Monitor");

            migrationBuilder.AddColumn<string>(
                name: "Reason",
                table: "Alerts",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "legacy");

            migrationBuilder.AddColumn<string>(
                name: "RuleName",
                table: "Alerts",
                type: "nvarchar(128)",
                maxLength: 128,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Action",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "Reason",
                table: "Alerts");

            migrationBuilder.DropColumn(
                name: "RuleName",
                table: "Alerts");
        }
    }
}

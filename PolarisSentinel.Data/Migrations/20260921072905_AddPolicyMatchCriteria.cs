using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PolarisSentinel.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class AddPolicyMatchCriteria : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "MatchAttackTypes",
                table: "Policies",
                type: "nvarchar(512)",
                maxLength: 512,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "MatchDestinationIp",
                table: "Policies",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<int>(
                name: "MatchDestinationPort",
                table: "Policies",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<byte>(
                name: "MatchProtocol",
                table: "Policies",
                type: "tinyint",
                nullable: false,
                defaultValue: (byte)0);

            migrationBuilder.AddColumn<string>(
                name: "MatchSourceIp",
                table: "Policies",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<int>(
                name: "MatchSourcePort",
                table: "Policies",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "MatchAttackTypes",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "MatchDestinationIp",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "MatchDestinationPort",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "MatchProtocol",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "MatchSourceIp",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "MatchSourcePort",
                table: "Policies");
        }
    }
}

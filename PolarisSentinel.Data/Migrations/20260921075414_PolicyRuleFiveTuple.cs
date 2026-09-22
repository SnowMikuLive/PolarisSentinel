using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PolarisSentinel.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class PolicyRuleFiveTuple : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "MatchSourcePort",
                table: "Policies",
                newName: "RuleSourcePort");

            migrationBuilder.RenameColumn(
                name: "MatchSourceIp",
                table: "Policies",
                newName: "RuleSourceIp");

            migrationBuilder.RenameColumn(
                name: "MatchDestinationPort",
                table: "Policies",
                newName: "RuleDestinationPort");

            migrationBuilder.RenameColumn(
                name: "MatchDestinationIp",
                table: "Policies",
                newName: "RuleDestinationIp");

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
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
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

            migrationBuilder.RenameColumn(
                name: "RuleSourcePort",
                table: "Policies",
                newName: "MatchSourcePort");

            migrationBuilder.RenameColumn(
                name: "RuleSourceIp",
                table: "Policies",
                newName: "MatchSourceIp");

            migrationBuilder.RenameColumn(
                name: "RuleDestinationPort",
                table: "Policies",
                newName: "MatchDestinationPort");

            migrationBuilder.RenameColumn(
                name: "RuleDestinationIp",
                table: "Policies",
                newName: "MatchDestinationIp");
        }
    }
}

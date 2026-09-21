using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PolarisSentinel.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class PolicyRuleActionsOnly : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Action",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "AttackType",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "RuleDestinationIp",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "RuleDestinationPort",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "RuleSourceIp",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "RuleSourcePort",
                table: "Policies");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Action",
                table: "Policies",
                type: "nvarchar(16)",
                maxLength: 16,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "AttackType",
                table: "Policies",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RuleDestinationIp",
                table: "Policies",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "RuleDestinationPort",
                table: "Policies",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "RuleSourceIp",
                table: "Policies",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "RuleSourcePort",
                table: "Policies",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }
    }
}

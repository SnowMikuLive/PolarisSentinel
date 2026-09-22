using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PolarisSentinel.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class RestoreRuleStatus : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsBlockRule",
                table: "Rules",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "Status",
                table: "Rules",
                type: "int",
                nullable: false,
                defaultValue: 0);

            //补齐IsBlockRule/Status后，用Action回填封禁标记。
            //Backfill IsBlockRule from Action after adding IsBlockRule/Status columns.
            migrationBuilder.Sql("UPDATE [Rules] SET [IsBlockRule] = 1 WHERE [Action] = 'Block'");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsBlockRule",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "Status",
                table: "Rules");
        }
    }
}

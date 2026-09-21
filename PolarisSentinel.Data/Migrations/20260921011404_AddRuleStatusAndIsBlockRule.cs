using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PolarisSentinel.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class AddRuleStatusAndIsBlockRule : Migration
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

            migrationBuilder.UpdateData(
                table: "Rules",
                keyColumn: "Id",
                keyValue: "R-1",
                columns: new[] { "IsBlockRule", "Status" },
                values: new object[] { true, 0 });

            migrationBuilder.UpdateData(
                table: "Rules",
                keyColumn: "Id",
                keyValue: "R-2",
                columns: new[] { "IsBlockRule", "Status" },
                values: new object[] { true, 0 });
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

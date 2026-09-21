using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PolarisSentinel.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class RemoveCaptureTuningFromPolicy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "FlowIdleTimeoutMilliseconds",
                table: "Policies");

            migrationBuilder.DropColumn(
                name: "PreFilterMinPackets",
                table: "Policies");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "FlowIdleTimeoutMilliseconds",
                table: "Policies",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "PreFilterMinPackets",
                table: "Policies",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }
    }
}

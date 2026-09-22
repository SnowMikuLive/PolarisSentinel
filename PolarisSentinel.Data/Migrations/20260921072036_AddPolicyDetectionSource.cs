using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PolarisSentinel.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class AddPolicyDetectionSource : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "DetectionSource",
                table: "Policies",
                type: "nvarchar(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "RandomForest");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DetectionSource",
                table: "Policies");
        }
    }
}

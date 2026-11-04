using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using PolarisSentinel.DataAccess.Data;

namespace PolarisSentinel.DataAccess.Migrations;

[DbContext(typeof(SentinelDbContext))]
[Migration("20261104000000_PersistTrafficDecisionReasons")]
public partial class PersistTrafficDecisionReasons : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>("DecisionReason", "TrafficRecords", type: "nvarchar(max)", nullable: false, defaultValue: "");
        migrationBuilder.AddColumn<string>("DecisionText", "TrafficRecords", type: "nvarchar(max)", nullable: false, defaultValue: "");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn("DecisionReason", "TrafficRecords");
        migrationBuilder.DropColumn("DecisionText", "TrafficRecords");
    }
}

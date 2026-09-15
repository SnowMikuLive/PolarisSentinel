using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Data;

// 检测审计数据上下文，与 Identity 库分离
// Detection/audit DbContext, separate from Identity
public class SentinelDbContext : DbContext
{
    public SentinelDbContext(DbContextOptions<SentinelDbContext> options)
        : base(options)
    {
    }

    public DbSet<DetectionEvent> DetectionEvents => Set<DetectionEvent>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<DetectionEvent>(entity =>
        {
            entity.ToTable("DetectionEvents");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.SourceIp).HasMaxLength(45).IsRequired();
            entity.Property(e => e.DestinationIp).HasMaxLength(45).IsRequired();
            entity.Property(e => e.AttackType).HasMaxLength(64).IsRequired();
            entity.Property(e => e.Reason).HasMaxLength(128).IsRequired();
            entity.Property(e => e.Action).HasConversion<string>().HasMaxLength(16);
            entity.Property(e => e.Source).HasConversion<string>().HasMaxLength(32);
            entity.Property(e => e.RuleName).HasMaxLength(128);
            entity.HasIndex(e => e.DecidedAt);
            entity.HasIndex(e => e.SourceIp);
        });
    }
}

using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Data;

// Persistence context for the detection/audit bounded context.
// Separate from the identity context (ApplicationDbContext) which stays in the
// web host because it is tightly coupled to ASP.NET Core Identity.
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
            entity.HasIndex(e => e.DecidedAt);
            entity.HasIndex(e => e.SourceIp);
        });
    }
}

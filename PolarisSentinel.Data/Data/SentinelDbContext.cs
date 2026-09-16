using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Data;

public class SentinelDbContext : DbContext
{
    public SentinelDbContext(DbContextOptions<SentinelDbContext> options)
        : base(options)
    {
    }

    public DbSet<Policy> Policies => Set<Policy>();

    public DbSet<Alert> Alerts => Set<Alert>();

    public DbSet<Rule> Rules => Set<Rule>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Policy>(e =>
        {
            e.ToTable("Policies");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(128).IsRequired();
            e.Property(x => x.UserId).HasMaxLength(450).IsRequired();
            e.Property(x => x.Action).HasConversion<string>().HasMaxLength(16);

            e.HasData(
                new Policy
                {
                    Id = Guid.Parse("11111111-1111-1111-1111-111111111111"),
                    Name = "Default Monitor",
                    UserId = string.Empty,
                    Action = PolicyAction.Monitor,
                    RfConfidenceThreshold = 0.6f,
                    AutoBlockConfidenceThreshold = 0.8f,
                    BlockDurationMinutes = 60,
                    DecisionCooldownSeconds = 60,
                    IsActive = true,
                    CreatedAt = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                },
                new Policy
                {
                    Id = Guid.Parse("22222222-2222-2222-2222-222222222222"),
                    Name = "Default Block",
                    UserId = string.Empty,
                    Action = PolicyAction.Block,
                    RfConfidenceThreshold = 0.7f,
                    AutoBlockConfidenceThreshold = 0.9f,
                    BlockDurationMinutes = 120,
                    DecisionCooldownSeconds = 30,
                    IsActive = true,
                    CreatedAt = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                });
        });

        modelBuilder.Entity<Alert>(e =>
        {
            e.ToTable("Alerts");
            e.HasKey(x => x.Id);
            e.Property(x => x.SourceIp).HasMaxLength(45).IsRequired();
            e.Property(x => x.DestinationIp).HasMaxLength(45).IsRequired();
            e.Property(x => x.AttackType).HasMaxLength(64).IsRequired();
            e.Property(x => x.Severity).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.Source).HasConversion<string>().HasMaxLength(32);
            e.HasIndex(x => x.DetectedAt);
            e.HasIndex(x => x.SourceIp);
        });

        modelBuilder.Entity<Rule>(e =>
        {
            e.ToTable("Rules");
            e.HasKey(x => x.Id);
            e.Property(x => x.RemoteAddress).HasMaxLength(45).IsRequired();
            e.Property(x => x.Status).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.Action).HasConversion<string>().HasMaxLength(16);
            e.HasOne(x => x.Policy)
                .WithMany()
                .HasForeignKey(x => x.PolicyId)
                .OnDelete(DeleteBehavior.SetNull);
            e.HasOne(x => x.Alert)
                .WithMany()
                .HasForeignKey(x => x.AlertId)
                .OnDelete(DeleteBehavior.SetNull);
        });
    }
}

using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.DataAccess.Data;

public class SentinelDbContext : IdentityDbContext
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
            e.Property(x => x.Id).HasMaxLength(32);
            e.Property(x => x.Name).HasMaxLength(128).IsRequired();
            e.Property(x => x.Description).HasMaxLength(512);
            e.Property(x => x.UserId).HasMaxLength(450).IsRequired();
            e.Property(x => x.DetectionSource).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.Action).HasConversion<string>().HasMaxLength(16);

            // Runtime settings (merged from PolicySettings) are appsettings config, not per-policy columns.
            e.Ignore(x => x.IfAnomalyThreshold);
            e.Ignore(x => x.FlowIdleTimeoutMilliseconds);
            e.Ignore(x => x.PreFilterMinPackets);
            e.Ignore(x => x.Allowlist);

            // Decision fields (merged from PolicyDecision) are transient engine output, not stored per policy.
            e.Ignore(x => x.AlertId);
            e.Ignore(x => x.SourceIp);
            e.Ignore(x => x.AttackType);
            e.Ignore(x => x.Confidence);
            e.Ignore(x => x.DecidedAt);
            e.Ignore(x => x.Reason);
            e.Ignore(x => x.RuleName);

            e.HasData(
                new Policy
                {
                    Id = "P-1",
                    Name = "Default Monitor",
                    UserId = string.Empty,
                    DetectionSource = DetectionSource.RandomForest,
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
                    Id = "P-2",
                    Name = "Default Block",
                    UserId = string.Empty,
                    DetectionSource = DetectionSource.RandomForest,
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
            e.Property(x => x.Id).HasMaxLength(32);
            e.Property(x => x.SourceIp).HasMaxLength(45).IsRequired();
            e.Property(x => x.DestinationIp).HasMaxLength(45).IsRequired();
            e.Property(x => x.AttackType).HasMaxLength(64).IsRequired();
            e.Property(x => x.Severity).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.Source).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.Action).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.RuleName).HasMaxLength(128);
            e.Property(x => x.Reason).HasMaxLength(128).IsRequired();
            e.HasIndex(x => x.DetectedAt);
            e.HasIndex(x => x.SourceIp);

            // Test/audit seed data: two alerts that produced rules R-1 and R-2.
            e.HasData(
                new Alert
                {
                    Id = "A-RF-1",
                    SourceIp = "203.0.113.10",
                    SourcePort = 44321,
                    DestinationIp = "192.168.1.10",
                    DestinationPort = 80,
                    Protocol = 6,
                    AttackType = AttackTypes.DoS,
                    Confidence = 0.95f,
                    Severity = Severity.High,
                    Source = DetectionSource.RandomForest,
                    DetectedAt = new DateTime(2026, 1, 2, 10, 0, 0, DateTimeKind.Utc),
                    Action = PolicyAction.Block,
                    RuleName = "PolarisSentinel_Block_A-RF-1",
                    Reason = "rf_block_confidence"
                },
                new Alert
                {
                    Id = "A-RF-2",
                    SourceIp = "198.51.100.23",
                    SourcePort = 51234,
                    DestinationIp = "192.168.1.10",
                    DestinationPort = 22,
                    Protocol = 6,
                    AttackType = AttackTypes.PortScan,
                    Confidence = 0.88f,
                    Severity = Severity.Medium,
                    Source = DetectionSource.RandomForest,
                    DetectedAt = new DateTime(2026, 1, 2, 12, 0, 0, DateTimeKind.Utc),
                    Action = PolicyAction.Block,
                    RuleName = "PolarisSentinel_Block_A-RF-2",
                    Reason = "rf_block_confidence"
                });
        });

        modelBuilder.Entity<Rule>(e =>
        {
            e.ToTable("Rules");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasMaxLength(32);
            e.Property(x => x.Name).HasMaxLength(128);
            e.Property(x => x.RemoteAddress).HasMaxLength(45).IsRequired();
            e.Property(x => x.Status).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.Action).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.AttackType).HasMaxLength(64);
            e.HasOne(x => x.Policy)
                .WithMany()
                .HasForeignKey(x => x.PolicyId)
                .OnDelete(DeleteBehavior.SetNull);
            e.HasOne(x => x.Alert)
                .WithMany()
                .HasForeignKey(x => x.AlertId)
                .OnDelete(DeleteBehavior.SetNull);

            // Test/audit seed data: two alerts and the two rules they produced.
            e.HasData(
                new Rule
                {
                    Id = "R-1",
                    Name = "PolarisSentinel_Block_A-RF-1",
                    PolicyId = "P-2",
                    AlertId = "A-RF-1",
                    Action = PolicyAction.Block,
                    RemoteAddress = "203.0.113.10",
                    Status = RuleStatus.Active,
                    Enabled = true,
                    IsBlockRule = true,
                    AttackType = AttackTypes.DoS,
                    CreatedAt = new DateTime(2026, 1, 2, 10, 0, 0, DateTimeKind.Utc),
                    ExpiresAt = new DateTime(2026, 1, 2, 11, 0, 0, DateTimeKind.Utc)
                },
                new Rule
                {
                    Id = "R-2",
                    Name = "PolarisSentinel_Block_A-RF-2",
                    PolicyId = "P-2",
                    AlertId = "A-RF-2",
                    Action = PolicyAction.Block,
                    RemoteAddress = "198.51.100.23",
                    Status = RuleStatus.Active,
                    Enabled = true,
                    IsBlockRule = true,
                    AttackType = AttackTypes.PortScan,
                    CreatedAt = new DateTime(2026, 1, 2, 12, 0, 0, DateTimeKind.Utc),
                    ExpiresAt = new DateTime(2026, 1, 2, 13, 0, 0, DateTimeKind.Utc)
                });
        });
    }
}

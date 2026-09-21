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
            e.Property(x => x.UserId).HasMaxLength(450).IsRequired();
            e.Property(x => x.MatchAttackTypes).HasMaxLength(512);
            e.Property(x => x.RuleSourceIpAction).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.RuleSourcePortAction).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.RuleDestinationIpAction).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.RuleDestinationPortAction).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.DetectionSource).HasConversion<string>().HasMaxLength(32);
        });

        modelBuilder.Entity<Alert>(e =>
        {
            e.ToTable("Alerts");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasMaxLength(32);
            e.Property(x => x.SourceIp).HasMaxLength(45).IsRequired();
            e.Property(x => x.DestinationIp).HasMaxLength(45).IsRequired();
            e.Property(x => x.AttackType).HasMaxLength(64).IsRequired();
            e.Property(x => x.Source).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.Action).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.RuleName).HasMaxLength(128);
            e.Property(x => x.Reason).HasMaxLength(128).IsRequired();
            e.HasIndex(x => x.DetectedAt);
            e.HasIndex(x => x.SourceIp);
        });

        modelBuilder.Entity<Rule>(e =>
        {
            e.ToTable("Rules");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasMaxLength(32);
            e.Property(x => x.Name).HasMaxLength(128);
            e.Property(x => x.Action).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.SourceIp).HasMaxLength(64);
            e.Property(x => x.DestinationIp).HasMaxLength(64);
            e.Property(x => x.AttackType).HasMaxLength(64);
            e.HasOne(x => x.Policy)
                .WithMany()
                .HasForeignKey(x => x.PolicyId)
                .OnDelete(DeleteBehavior.SetNull);
            e.HasOne(x => x.Alert)
                .WithMany()
                .HasForeignKey(x => x.AlertId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<Policy>().HasData(DemoPolicies);
    }

    private static readonly DateTime SeedTimestamp = new DateTime(2026, 9, 21, 0, 0, 0, DateTimeKind.Unspecified);

    private static readonly Policy[] DemoPolicies =
    {
        new()
        {
            Id = "P-1",
            UserId = "admin",
            DetectionSource = DetectionSource.PreFilter,
            RfConfidenceThreshold = null,
            IfConfidenceThreshold = null,
            BlockDurationMinutes = 10,
            MatchAttackTypes = null,
            MatchProtocol = 0,
            RuleSourceIpAction = PolicyAction.Block,
            RuleSourcePortAction = PolicyAction.Allow,
            RuleDestinationIpAction = PolicyAction.Allow,
            RuleDestinationPortAction = PolicyAction.Allow,
            CreatedAt = SeedTimestamp,
            UpdatedAt = SeedTimestamp
        },
        new()
        {
            Id = "P-2",
            UserId = "admin",
            DetectionSource = DetectionSource.PreFilter,
            RfConfidenceThreshold = null,
            IfConfidenceThreshold = null,
            BlockDurationMinutes = 10,
            MatchAttackTypes = AttackTypes.DoS,
            MatchProtocol = 0,
            RuleSourceIpAction = PolicyAction.Block,
            RuleSourcePortAction = PolicyAction.Block,
            RuleDestinationIpAction = PolicyAction.Allow,
            RuleDestinationPortAction = PolicyAction.Allow,
            CreatedAt = SeedTimestamp,
            UpdatedAt = SeedTimestamp
        },
        new()
        {
            Id = "P-3",
            UserId = "admin",
            DetectionSource = DetectionSource.PreFilter,
            RfConfidenceThreshold = null,
            IfConfidenceThreshold = null,
            BlockDurationMinutes = 10,
            MatchAttackTypes = AttackTypes.DoS,
            MatchProtocol = ProtocolNumbers.Icmp,
            RuleSourceIpAction = PolicyAction.Block,
            RuleSourcePortAction = PolicyAction.Allow,
            RuleDestinationIpAction = PolicyAction.Allow,
            RuleDestinationPortAction = PolicyAction.Allow,
            CreatedAt = SeedTimestamp,
            UpdatedAt = SeedTimestamp
        },
        new()
        {
            Id = "P-4",
            UserId = "admin",
            DetectionSource = DetectionSource.PreFilter,
            RfConfidenceThreshold = null,
            IfConfidenceThreshold = null,
            BlockDurationMinutes = 10,
            MatchAttackTypes = AttackTypes.DoS,
            MatchProtocol = ProtocolNumbers.Udp,
            RuleSourceIpAction = PolicyAction.Block,
            RuleSourcePortAction = PolicyAction.Allow,
            RuleDestinationIpAction = PolicyAction.Allow,
            RuleDestinationPortAction = PolicyAction.Allow,
            CreatedAt = SeedTimestamp,
            UpdatedAt = SeedTimestamp
        },
        new()
        {
            Id = "P-5",
            UserId = "admin",
            DetectionSource = DetectionSource.RandomForest,
            RfConfidenceThreshold = 0.6f,
            IfConfidenceThreshold = null,
            BlockDurationMinutes = 10,
            MatchAttackTypes = null,
            MatchProtocol = 0,
            RuleSourceIpAction = PolicyAction.Block,
            RuleSourcePortAction = PolicyAction.Allow,
            RuleDestinationIpAction = PolicyAction.Allow,
            RuleDestinationPortAction = PolicyAction.Allow,
            CreatedAt = SeedTimestamp,
            UpdatedAt = SeedTimestamp
        }
    };
}

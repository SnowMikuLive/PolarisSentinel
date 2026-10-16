using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.DataAccess.Data;

public class SentinelDbContext : IdentityDbContext<ApplicationUser>
{
    public SentinelDbContext(DbContextOptions<SentinelDbContext> options)
        : base(options)
    {
    }

    public DbSet<Policy> Policies => Set<Policy>();

    public DbSet<Alert> Alerts => Set<Alert>();

    public DbSet<Rule> Rules => Set<Rule>();

    public DbSet<TrafficRecord> TrafficRecords => Set<TrafficRecord>();

    public DbSet<UserSettings> UserSettings => Set<UserSettings>();

    private static readonly ValueConverter<DetectionSource, string> DetectionSourceConverter = new(
        source => source.ToString(),
        value => ParseDetectionSource(value));

    private static DetectionSource ParseDetectionSource(string value) =>
        Enum.TryParse<DetectionSource>(value, ignoreCase: true, out var parsed)
            ? parsed
            : DetectionSource.None;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Policy>(e =>
        {
            e.ToTable("Policies");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasMaxLength(32);
            e.Property(x => x.UserId).HasMaxLength(450).IsRequired();
            e.Property(x => x.Name).HasMaxLength(128).IsRequired();
            e.Property(x => x.Description).HasMaxLength(512);
            e.Property(x => x.AttackType).HasMaxLength(64);
            e.Property(x => x.DetectionSource).HasConversion(DetectionSourceConverter).HasMaxLength(32);
            e.Property(x => x.Action).HasConversion<string>().HasMaxLength(32);
        });

        modelBuilder.Entity<Alert>(e =>
        {
            e.ToTable("Alerts");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasMaxLength(32);
            e.Property(x => x.SourceIp).HasMaxLength(45).IsRequired();
            e.Property(x => x.DestinationIp).HasMaxLength(45).IsRequired();
            e.Property(x => x.AttackType).HasMaxLength(64).IsRequired();
            e.Property(x => x.Description).HasMaxLength(256);
            e.Property(x => x.DetectionSource).HasConversion(DetectionSourceConverter).HasMaxLength(32);
            e.HasIndex(x => x.CreatedAt);
            e.HasIndex(x => x.SourceIp);
        });

        modelBuilder.Entity<Rule>(e =>
        {
            e.ToTable("Rules");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasMaxLength(32);
            e.Property(x => x.Name).HasMaxLength(128);
            e.Property(x => x.Action).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.Status).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.SourceIp).HasMaxLength(64);
            e.Property(x => x.DestinationIp).HasMaxLength(64);
            e.HasOne<Policy>()
                .WithMany()
                .HasForeignKey(x => x.PolicyId)
                .OnDelete(DeleteBehavior.SetNull);
            e.HasOne<Alert>()
                .WithMany()
                .HasForeignKey(x => x.AlertId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<TrafficRecord>(e =>
        {
            e.ToTable("TrafficRecords");
            e.HasKey(x => x.Id);
            e.Property(x => x.AlertId).HasMaxLength(32);
            e.Property(x => x.SourceIp).HasMaxLength(45);
            e.Property(x => x.DestinationIp).HasMaxLength(45);
            e.Property(x => x.AttackType).HasMaxLength(64);
            e.Property(x => x.Action).HasMaxLength(32);
            e.Property(x => x.Reason).HasMaxLength(256);
            e.Property(x => x.Source).HasMaxLength(32);
            e.Property(x => x.RuleName).HasMaxLength(128);
            e.Property(x => x.Verdict).HasMaxLength(16);
            e.HasIndex(x => x.CreatedAt);
        });

        modelBuilder.Entity<UserSettings>(e =>
        {
            e.ToTable("UserSettings");
            e.HasKey(x => x.Id);
            e.Property(x => x.ModelCombination).HasMaxLength(64);
            e.Property(x => x.CaptureDevice).HasMaxLength(256);
        });

        modelBuilder.Entity<Policy>().HasData(DefaultPolicies);
    }

    private static readonly DateTime SeedTimestamp = new DateTime(2026, 9, 26, 0, 0, 0, DateTimeKind.Unspecified);

    private static readonly Policy[] DefaultPolicies =
    {
        new()
        {
            Id = "P-1",
            UserId = "admin",
            Name = "Heuristic DoS",
            Description = "Block the source of any rule-based DoS detection.",
            DetectionSource = DetectionSource.HeuristicBased,
            RfThreshold = null,
            IfThreshold = null,
            AttackType = AttackTypes.DoS,
            Action = PolicyAction.BlockInboundIp,
            BlockDurationMinutes = 60,
            Priority = 100,
            IsEnabled = true,
            CreatedAt = SeedTimestamp,
            UpdatedAt = SeedTimestamp
        },
        new()
        {
            Id = "P-2",
            UserId = "admin",
            Name = "Random Forest PortScan",
            Description = "Block the scanning source of a Random Forest port scan detection (reconnaissance: short block).",
            DetectionSource = DetectionSource.RandomForest,
            RfThreshold = 0.5f,
            IfThreshold = null,
            AttackType = AttackTypes.PortScan,
            Action = PolicyAction.BlockInboundIp,
            BlockDurationMinutes = 30,
            Priority = 90,
            IsEnabled = true,
            CreatedAt = SeedTimestamp,
            UpdatedAt = SeedTimestamp
        },
        new()
        {
            Id = "P-3",
            UserId = "admin",
            Name = "Random Forest BruteForce",
            Description = "Block the source of a Random Forest brute force detection (credential attack: long block).",
            DetectionSource = DetectionSource.RandomForest,
            RfThreshold = 0.5f,
            IfThreshold = null,
            AttackType = AttackTypes.BruteForce,
            Action = PolicyAction.BlockInboundIp,
            BlockDurationMinutes = 120,
            Priority = 90,
            IsEnabled = true,
            CreatedAt = SeedTimestamp,
            UpdatedAt = SeedTimestamp
        },
        new()
        {
            Id = "P-4",
            UserId = "admin",
            Name = "Heuristic PortScan",
            Description = "Block the scanning source of any rule-based port scan detection (reconnaissance: short block).",
            DetectionSource = DetectionSource.HeuristicBased,
            RfThreshold = null,
            IfThreshold = null,
            AttackType = AttackTypes.PortScan,
            Action = PolicyAction.BlockInboundIp,
            BlockDurationMinutes = 30,
            Priority = 100,
            IsEnabled = true,
            CreatedAt = SeedTimestamp,
            UpdatedAt = SeedTimestamp
        },
        new()
        {
            Id = "P-5",
            UserId = "admin",
            Name = "Heuristic BruteForce",
            Description = "Block the source of any rule-based brute force detection (credential attack: long block).",
            DetectionSource = DetectionSource.HeuristicBased,
            RfThreshold = null,
            IfThreshold = null,
            AttackType = AttackTypes.BruteForce,
            Action = PolicyAction.BlockInboundIp,
            BlockDurationMinutes = 120,
            Priority = 100,
            IsEnabled = true,
            CreatedAt = SeedTimestamp,
            UpdatedAt = SeedTimestamp
        },

        new()
        {
            Id = "P-6",
            UserId = "admin",
            Name = "Isolation Forest anomaly",
            Description = "Surface an unnamed Isolation Forest anomaly for review. Monitor-only: an unnamed anomaly is suspicious, not a confirmed attack.",
            DetectionSource = DetectionSource.IsolationForest,
            RfThreshold = null,
            IfThreshold = 0.5f,
            AttackType = AttackTypes.UnknownAnomaly,
            Action = PolicyAction.Monitor,
            BlockDurationMinutes = 0,
            Priority = 90,
            IsEnabled = true,
            CreatedAt = SeedTimestamp,
            UpdatedAt = SeedTimestamp
        },
        new()
        {
            Id = "P-7",
            UserId = "admin",
            Name = "Random Forest DoS",
            Description = "Block the source of a Random Forest DoS detection (availability attack).",
            DetectionSource = DetectionSource.RandomForest,
            RfThreshold = 0.5f,
            IfThreshold = null,
            AttackType = AttackTypes.DoS,
            Action = PolicyAction.BlockInboundIp,
            BlockDurationMinutes = 60,
            Priority = 90,
            IsEnabled = true,
            CreatedAt = SeedTimestamp,
            UpdatedAt = SeedTimestamp
        }
    };
}

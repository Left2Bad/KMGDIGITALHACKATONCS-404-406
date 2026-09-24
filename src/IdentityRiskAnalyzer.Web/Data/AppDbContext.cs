using IdentityRiskAnalyzer.Web.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IdentityRiskAnalyzer.Web.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<ScanRun> ScanRuns => Set<ScanRun>();
    public DbSet<AdObjectSnapshot> AdObjectSnapshots => Set<AdObjectSnapshot>();
    public DbSet<GroupMembership> GroupMemberships => Set<GroupMembership>();
    public DbSet<DelegationRecord> DelegationRecords => Set<DelegationRecord>();
    public DbSet<RiskFinding> RiskFindings => Set<RiskFinding>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<ScanRun>(entity =>
        {
            entity.HasKey(scanRun => scanRun.Id);
            entity.Property(scanRun => scanRun.Server).IsRequired();
            entity.Property(scanRun => scanRun.BaseDn).IsRequired();
        });

        modelBuilder.Entity<AdObjectSnapshot>(entity =>
        {
            entity.HasKey(snapshot => snapshot.Id);
            entity.Property(snapshot => snapshot.DistinguishedName).IsRequired();
            entity.HasIndex(snapshot => new { snapshot.ScanRunId, snapshot.ObjectGuid });
            entity.HasIndex(snapshot => snapshot.ObjectGuid);
            entity.HasOne(snapshot => snapshot.ScanRun)
                .WithMany(scanRun => scanRun.AdObjectSnapshots)
                .HasForeignKey(snapshot => snapshot.ScanRunId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<GroupMembership>(entity =>
        {
            entity.HasKey(membership => membership.Id);
            entity.Property(membership => membership.GroupName).IsRequired();
            entity.Property(membership => membership.GroupDistinguishedName).IsRequired();
            entity.Property(membership => membership.PathJson).IsRequired();
            entity.HasIndex(membership => new { membership.ScanRunId, membership.PrincipalObjectGuid });
            entity.HasOne(membership => membership.ScanRun)
                .WithMany(scanRun => scanRun.GroupMemberships)
                .HasForeignKey(membership => membership.ScanRunId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<DelegationRecord>(entity =>
        {
            entity.HasKey(record => record.Id);
            entity.Property(record => record.ObjectName).IsRequired();
            entity.HasOne(record => record.ScanRun)
                .WithMany(scanRun => scanRun.DelegationRecords)
                .HasForeignKey(record => record.ScanRunId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<RiskFinding>(entity =>
        {
            entity.HasKey(finding => finding.Id);
            entity.Property(finding => finding.ObjectName).IsRequired();
            entity.Property(finding => finding.RuleId).IsRequired();
            entity.Property(finding => finding.Category).IsRequired();
            entity.Property(finding => finding.Title).IsRequired();
            entity.Property(finding => finding.Description).IsRequired();
            entity.Property(finding => finding.Recommendation).IsRequired();
            entity.HasIndex(finding => finding.ScanRunId);
            entity.HasIndex(finding => finding.ObjectGuid);
            entity.HasIndex(finding => finding.RuleId);
            entity.HasOne(finding => finding.ScanRun)
                .WithMany(scanRun => scanRun.RiskFindings)
                .HasForeignKey(finding => finding.ScanRunId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}

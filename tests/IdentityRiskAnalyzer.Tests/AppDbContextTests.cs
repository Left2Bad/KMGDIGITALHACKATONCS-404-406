using IdentityRiskAnalyzer.Web.Data;
using IdentityRiskAnalyzer.Web.Domain.Entities;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace IdentityRiskAnalyzer.Tests;

public class AppDbContextTests
{
    [Fact]
    public async Task SavesAndLoadsScanRunWithRelatedRiskFinding()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connection)
            .Options;

        await using (var dbContext = new AppDbContext(options))
        {
            await dbContext.Database.EnsureCreatedAsync();

            var scanRun = new ScanRun
            {
                StartedAtUtc = new DateTimeOffset(2026, 9, 24, 11, 30, 0, TimeSpan.FromHours(3)),
                Status = ScanStatus.Completed,
                Server = "dc01.example.test",
                BaseDn = "DC=example,DC=test",
                ObjectsScanned = 12,
                FindingsCount = 1,
                ErrorsCount = 0
            };
            scanRun.RiskFindings.Add(new RiskFinding
            {
                ObjectGuid = Guid.Parse("9f216d83-f5ca-4f7d-bf5e-45d3c2b7c20a"),
                ObjectType = AdObjectType.User,
                ObjectName = "ivan.petrov",
                RuleId = "IRA-ACCOUNT-001",
                Category = "Account",
                Title = "Inactive account",
                Description = "The account has not been active recently.",
                Recommendation = "Review the account with its owner.",
                RiskPoints = 25,
                Severity = RiskSeverity.Medium
            });

            dbContext.ScanRuns.Add(scanRun);
            await dbContext.SaveChangesAsync();
        }

        await using (var dbContext = new AppDbContext(options))
        {
            var loadedScan = await dbContext.ScanRuns
                .Include(scan => scan.RiskFindings)
                .SingleAsync();

            Assert.Equal(ScanStatus.Completed, loadedScan.Status);
            Assert.Equal(TimeSpan.Zero, loadedScan.StartedAtUtc.Offset);
            Assert.Equal(new DateTimeOffset(2026, 9, 24, 8, 30, 0, TimeSpan.Zero), loadedScan.StartedAtUtc);
            Assert.Equal("dc01.example.test", loadedScan.Server);
            Assert.Equal(12, loadedScan.ObjectsScanned);
            var finding = Assert.Single(loadedScan.RiskFindings);
            Assert.Equal("IRA-ACCOUNT-001", finding.RuleId);
            Assert.Equal("ivan.petrov", finding.ObjectName);
            Assert.Equal(25, finding.RiskPoints);
            Assert.Equal(RiskSeverity.Medium, finding.Severity);
        }
    }
}

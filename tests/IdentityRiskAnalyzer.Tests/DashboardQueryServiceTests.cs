using IdentityRiskAnalyzer.Web.Controllers;
using IdentityRiskAnalyzer.Web.Data;
using IdentityRiskAnalyzer.Web.Domain.Entities;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Services.Dashboard;
using IdentityRiskAnalyzer.Web.Services.RiskRules;
using IdentityRiskAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace IdentityRiskAnalyzer.Tests;

public sealed class DashboardQueryServiceTests
{
    private static readonly DateTimeOffset BaseTime = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task EmptyDatabaseShowsNoData()
    {
        await using var fixture = await Fixture.CreateAsync();
        var model = await fixture.Query.GetDashboardAsync();
        Assert.False(model.HasData);
        Assert.Null(model.AdSecurityScore);
        Assert.Null(model.LatestFailedScan);
        Assert.Empty(model.ScoreHistory);
    }

    [Fact]
    public async Task FailedOnlyIsWarningAndNeverSecuritySnapshot()
    {
        await using var fixture = await Fixture.CreateAsync();
        var failed = await fixture.AddScanAsync(ScanStatus.Failed, null, BaseTime,
            errorMessage: "Directory unavailable.");
        var model = await fixture.Query.GetDashboardAsync();
        Assert.False(model.HasData);
        Assert.Null(model.AdSecurityScore);
        Assert.Equal(failed.Id, model.LatestFailedScan?.ScanRunId);
        Assert.Equal("Directory unavailable.", model.LatestFailedScan?.ErrorMessage);
    }

    [Fact]
    public async Task CompletedSnapshotProvidesMetricsFromItsOwnSavedRows()
    {
        await using var fixture = await Fixture.CreateAsync();
        var run = await fixture.AddScanAsync(ScanStatus.Completed, 73, BaseTime);
        var high = Object(run.Id, "high", 75, RiskSeverity.Critical, privileged: true, service: true);
        var medium = Object(run.Id, "medium", 52, RiskSeverity.High, privileged: true);
        var low = Object(run.Id, "low", 12, RiskSeverity.Low, service: true);
        fixture.Db.AdObjectSnapshots.AddRange(high, medium, low);
        fixture.Db.RiskFindings.AddRange(
            Finding(run.Id, high, RiskSeverity.Critical, "Privilege", RiskRuleIds.StaleEnabledAccount),
            Finding(run.Id, high, RiskSeverity.High, "privilege", RiskRuleIds.StaleEnabledAccount),
            Finding(run.Id, medium, RiskSeverity.Medium, "Password", "IRA-PASSWORD-001"),
            Finding(run.Id, low, RiskSeverity.Low, "PASSWORD", "IRA-PASSWORD-002"));
        run.ObjectsScanned = 3;
        run.FindingsCount = 4;
        await fixture.Db.SaveChangesAsync();

        var model = await fixture.Query.GetDashboardAsync();
        Assert.True(model.HasData);
        Assert.Equal(run.Id, model.ScanRunId);
        Assert.Equal(73, model.AdSecurityScore);
        Assert.Equal(3, model.TotalObjects);
        Assert.Equal(4, model.TotalFindings);
        Assert.Equal(1, model.CriticalFindings);
        Assert.Equal(1, model.HighFindings);
        Assert.Equal(1, model.MediumFindings);
        Assert.Equal(1, model.LowFindings);
        Assert.Equal(1, model.CriticalObjects);
        Assert.Equal(1, model.HighObjects);
        Assert.Equal(0, model.MediumObjects);
        Assert.Equal(1, model.LowObjects);
        Assert.Equal(2, model.ServiceAccounts);
        Assert.Equal(2, model.PrivilegedAccounts);
        Assert.Equal(1, model.StaleAccounts); // Two matching findings belong to one account.
        Assert.Equal(["high", "medium", "low"], model.TopRiskyAccounts.Select(item => item.AccountName));
        Assert.Equal(2, model.RiskCategories.Count);
        Assert.Contains(model.RiskCategories, item => item.Category.Equals("Privilege", StringComparison.OrdinalIgnoreCase)
            && item.FindingsCount == 2 && item.AffectedAccounts == 1);
        Assert.Contains(model.RiskCategories, item => item.Category.Equals("Password", StringComparison.OrdinalIgnoreCase)
            && item.FindingsCount == 2 && item.AffectedAccounts == 2);
        Assert.Equal(["high", "medium"], model.HighRiskPrivilegedAccounts.Select(item => item.AccountName));
        Assert.Equal(["high", "low"], model.RiskyServiceAccounts.Select(item => item.AccountName));
        Assert.Equal(RiskSeverity.Critical, model.MostImportantFindings[0].Severity);
        Assert.Single(model.ScoreHistory);
    }

    [Fact]
    public async Task CompletedWithErrorsIsUsableAndLaterFailureDoesNotReplaceIt()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.AddScanAsync(ScanStatus.Completed, 81, BaseTime);
        var usable = await fixture.AddScanAsync(ScanStatus.CompletedWithErrors, 64, BaseTime.AddHours(1), errors: 2);
        var failed = await fixture.AddScanAsync(ScanStatus.Failed, null, BaseTime.AddHours(2), errorMessage: "LDAP failed.");

        var model = await fixture.Query.GetDashboardAsync();
        Assert.Equal(usable.Id, model.ScanRunId);
        Assert.Equal(ScanStatus.CompletedWithErrors, model.ScanStatus);
        Assert.Equal(2, model.ErrorsCount);
        Assert.Equal(64, model.AdSecurityScore);
        Assert.Equal(failed.Id, model.LatestFailedScan?.ScanRunId);
        Assert.Equal([81, 64], model.ScoreHistory.Select(item => item.AdSecurityScore));
        Assert.DoesNotContain(model.ScoreHistory, item => item.ScanRunId == failed.Id);
    }

    [Fact]
    public async Task FindingAndObjectSeverityCountsDoNotMix()
    {
        await using var fixture = await Fixture.CreateAsync();
        var run = await fixture.AddScanAsync(ScanStatus.Completed, 50, BaseTime);
        foreach (var severity in Enum.GetValues<RiskSeverity>())
        {
            var account = Object(run.Id, severity.ToString(), 10 + (int)severity, severity);
            fixture.Db.AdObjectSnapshots.Add(account);
            foreach (var index in Enumerable.Range(0, (int)severity + 2))
                fixture.Db.RiskFindings.Add(Finding(run.Id, account, severity, "Account", $"IRA-TEST-{severity}-{index}"));
        }
        await fixture.Db.SaveChangesAsync();
        var model = await fixture.Query.GetDashboardAsync();
        Assert.Equal((2, 3, 4, 5), (model.LowFindings, model.MediumFindings, model.HighFindings, model.CriticalFindings));
        Assert.Equal((1, 1, 1, 1), (model.LowObjects, model.MediumObjects, model.HighObjects, model.CriticalObjects));
    }

    [Fact]
    public async Task TopAccountsUseRiskCriticalFindingCountTotalFindingsAndNameTieBreaks()
    {
        await using var fixture = await Fixture.CreateAsync();
        var run = await fixture.AddScanAsync(ScanStatus.Completed, 40, BaseTime);
        var a = Object(run.Id, "Zeta", 80, RiskSeverity.Critical);
        var b = Object(run.Id, "Alpha", 80, RiskSeverity.Critical);
        var c = Object(run.Id, "Critical", 80, RiskSeverity.Critical);
        var d = Object(run.Id, "Lower", 70, RiskSeverity.High);
        var e = Object(run.Id, "TotalCount", 80, RiskSeverity.Critical);
        fixture.Db.AdObjectSnapshots.AddRange(a, b, c, d, e);
        fixture.Db.RiskFindings.AddRange(
            Finding(run.Id, a, RiskSeverity.High, "Account", "A"),
            Finding(run.Id, b, RiskSeverity.High, "Account", "B"),
            Finding(run.Id, c, RiskSeverity.Critical, "Account", "C"),
            Finding(run.Id, d, RiskSeverity.Critical, "Account", "D"),
            Finding(run.Id, e, RiskSeverity.High, "Account", "E-1"),
            Finding(run.Id, e, RiskSeverity.High, "Account", "E-2"));
        await fixture.Db.SaveChangesAsync();
        var model = await fixture.Query.GetDashboardAsync();
        Assert.Equal(["Critical", "TotalCount", "Alpha", "Zeta", "Lower"], model.TopRiskyAccounts.Select(item => item.AccountName));
    }

    [Fact]
    public async Task NullSecurityScoreAndRunningStateRemainDistinctFromZero()
    {
        await using var fixture = await Fixture.CreateAsync();
        var completed = await fixture.AddScanAsync(ScanStatus.Completed, null, BaseTime);
        await fixture.AddScanAsync(ScanStatus.Running, null, BaseTime.AddMinutes(10));
        var model = await fixture.Query.GetDashboardAsync();
        Assert.Equal(completed.Id, model.ScanRunId);
        Assert.Null(model.AdSecurityScore);
        Assert.True(model.ScanRunning);
        Assert.Single(model.ScoreHistory);
        Assert.Null(model.ScoreHistory[0].AdSecurityScore);
    }

    [Fact]
    public async Task ImportantFindingsSortBySeverityThenPointsThenAccountRisk()
    {
        await using var fixture = await Fixture.CreateAsync();
        var run = await fixture.AddScanAsync(ScanStatus.Completed, 45, BaseTime);
        var highRisk = Object(run.Id, "high-risk", 90, RiskSeverity.Critical);
        var lowerRisk = Object(run.Id, "lower-risk", 40, RiskSeverity.Medium);
        fixture.Db.AdObjectSnapshots.AddRange(highRisk, lowerRisk);
        var highest = Finding(run.Id, lowerRisk, RiskSeverity.Critical, "Account", "HIGHEST");
        highest.RiskPoints = 50;
        var samePointsHigherAccountRisk = Finding(run.Id, highRisk, RiskSeverity.Critical, "Account", "HIGHER-ACCOUNT");
        samePointsHigherAccountRisk.RiskPoints = 30;
        var samePointsLowerAccountRisk = Finding(run.Id, lowerRisk, RiskSeverity.Critical, "Account", "LOWER-ACCOUNT");
        samePointsLowerAccountRisk.RiskPoints = 30;
        fixture.Db.RiskFindings.AddRange(highest, samePointsHigherAccountRisk,
            samePointsLowerAccountRisk, Finding(run.Id, highRisk, RiskSeverity.High, "Account", "HIGH"));
        await fixture.Db.SaveChangesAsync();
        var model = await fixture.Query.GetDashboardAsync();
        Assert.Equal(["HIGHEST", "HIGHER-ACCOUNT", "LOWER-ACCOUNT", "HIGH"],
            model.MostImportantFindings.Select(item => item.RuleId));
    }

    [Fact]
    public async Task HistoryKeepsLastTenUsableScansInChronologicalOrder()
    {
        await using var fixture = await Fixture.CreateAsync();
        for (var index = 0; index < 12; index++)
            await fixture.AddScanAsync(index == 6 ? ScanStatus.CompletedWithErrors : ScanStatus.Completed,
                index, BaseTime.AddHours(index));
        await fixture.AddScanAsync(ScanStatus.Failed, null, BaseTime.AddHours(12));

        var model = await fixture.Query.GetDashboardAsync();
        Assert.Equal(10, model.ScoreHistory.Count);
        Assert.Equal(Enumerable.Range(2, 10).Cast<int?>(), model.ScoreHistory.Select(item => item.AdSecurityScore));
        Assert.Equal(11, model.AdSecurityScore);
        Assert.NotNull(model.LatestFailedScan);
    }

    [Fact]
    public async Task ControllerReturnsDashboardViewModelWithoutLdapDependency()
    {
        await using var fixture = await Fixture.CreateAsync();
        var controller = new DashboardController(fixture.Query);
        var result = await controller.Index(CancellationToken.None);
        Assert.IsType<DashboardViewModel>(Assert.IsType<ViewResult>(result).Model);
    }

    private static AdObjectSnapshot Object(long scanRunId, string name, int riskScore,
        RiskSeverity level, bool privileged = false, bool service = false) => new()
    {
        ScanRunId = scanRunId, ObjectGuid = Guid.NewGuid(), SamAccountName = name,
        DistinguishedName = $"CN={name},DC=adlab,DC=test", RiskScore = riskScore,
        RiskLevel = level, IsPrivileged = privileged, IsServiceAccount = service
    };

    private static RiskFinding Finding(long scanRunId, AdObjectSnapshot account,
        RiskSeverity severity, string category, string ruleId) => new()
    {
        ScanRunId = scanRunId, ObjectGuid = account.ObjectGuid, ObjectType = AdObjectType.User,
        ObjectName = account.SamAccountName!, Severity = severity, Category = category,
        RuleId = ruleId, Title = "Test finding", Description = "Test description",
        Recommendation = "Review", RiskPoints = 10
    };

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        public AppDbContext Db { get; }
        public DashboardQueryService Query { get; }

        private Fixture(SqliteConnection connection, AppDbContext db)
        { _connection = connection; Db = db; Query = new DashboardQueryService(db); }

        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.MigrateAsync();
            return new Fixture(connection, db);
        }

        public async Task<ScanRun> AddScanAsync(ScanStatus status, int? score,
            DateTimeOffset startedAt, int errors = 0, string? errorMessage = null)
        {
            var run = new ScanRun
            {
                StartedAtUtc = startedAt, FinishedAtUtc = startedAt.AddMinutes(3),
                Status = status, Server = "dc01.adlab.test", BaseDn = "DC=adlab,DC=test",
                AdSecurityScore = score, ErrorsCount = errors, ErrorMessage = errorMessage
            };
            Db.ScanRuns.Add(run);
            await Db.SaveChangesAsync();
            return run;
        }

        public async ValueTask DisposeAsync()
        { await Db.DisposeAsync(); await _connection.DisposeAsync(); }
    }
}

using System.Text.Json;
using IdentityRiskAnalyzer.Web.Controllers;
using IdentityRiskAnalyzer.Web.Data;
using IdentityRiskAnalyzer.Web.Domain.Entities;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Services.Objects;
using IdentityRiskAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace IdentityRiskAnalyzer.Tests;

public sealed class ObjectDetailsQueryServiceTests
{
    private static readonly Guid ObjectGuid = Guid.Parse("52ff691d-4cbb-4c46-8b71-0c681d91ada0");

    [Fact]
    public async Task NormalHistoricalObjectLoadsSnapshotAndNullableStatus()
    {
        await using var fixture = await Fixture.CreateAsync();
        var scan = await fixture.AddScanAsync();
        fixture.Db.AdObjectSnapshots.Add(Snapshot(scan.Id, 82, RiskSeverity.Critical,
            enabled: null, locked: null, expired: null));
        await fixture.Db.SaveChangesAsync();

        var model = await fixture.Query.GetAsync(scan.Id, ObjectGuid);
        Assert.NotNull(model);
        Assert.Equal(scan.Id, model.ScanRunId);
        Assert.Equal(scan.StartedAtUtc, model.ScanTimestampUtc);
        Assert.Equal(ObjectGuid, model.ObjectGuid);
        Assert.Equal(82, model.RiskScore);
        Assert.Equal(RiskSeverity.Critical, model.RiskLevel);
        Assert.Null(model.Enabled);
        Assert.Null(model.Locked);
        Assert.Null(model.AccountExpired);
        Assert.Null(model.UserPrincipalName);
        Assert.Null(model.Sid);
        Assert.Null(model.LastKnownActivityUtc);
        Assert.Null(model.PasswordLastSetUtc);
        Assert.Equal(0, model.FindingsCount);
        Assert.Equal(0, model.AccumulatedPoints);
    }

    [Fact]
    public async Task SameObjectGuidRetainsDifferentRiskAndFindingsAcrossScans()
    {
        await using var fixture = await Fixture.CreateAsync();
        var first = await fixture.AddScanAsync();
        var second = await fixture.AddScanAsync();
        fixture.Db.AdObjectSnapshots.AddRange(Snapshot(first.Id, 80, RiskSeverity.Critical),
            Snapshot(second.Id, 20, RiskSeverity.Low));
        fixture.Db.RiskFindings.AddRange(Finding(first.Id, RiskSeverity.Critical, 80, "FIRST"),
            Finding(second.Id, RiskSeverity.Low, 20, "SECOND"));
        fixture.Db.GroupMemberships.AddRange(
            Membership(first.Id, "Old Admins", 1, true, true, ["ivan", "Old Admins"]),
            Membership(second.Id, "New Users", 1, true, false, ["ivan", "New Users"]));
        fixture.Db.DelegationRecords.AddRange(
            Delegation(first.Id, DelegationType.Unconstrained, null),
            Delegation(second.Id, DelegationType.Constrained, "[\"HTTP/new\"]"));
        await fixture.Db.SaveChangesAsync();

        var old = await fixture.Query.GetAsync(first.Id, ObjectGuid);
        var current = await fixture.Query.GetAsync(second.Id, ObjectGuid);
        Assert.Equal(80, old?.RiskScore);
        Assert.Equal("FIRST", Assert.Single(old!.Findings).RuleId);
        Assert.Equal("Old Admins", Assert.Single(old.PrivilegeMemberships).GroupName);
        Assert.Equal(DelegationType.Unconstrained, Assert.Single(old.DelegationRecords).DelegationType);
        Assert.Equal(20, current?.RiskScore);
        Assert.Equal("SECOND", Assert.Single(current!.Findings).RuleId);
        Assert.Empty(current.PrivilegeMemberships);
        Assert.Equal("New Users", Assert.Single(current.GroupMemberships).GroupName);
        Assert.Equal(DelegationType.Constrained, Assert.Single(current.DelegationRecords).DelegationType);
    }

    [Fact]
    public async Task PrivilegedAndOrdinaryMembershipsKeepDirectNestedDepthAndPathOrder()
    {
        await using var fixture = await Fixture.CreateAsync();
        var scan = await fixture.AddScanAsync();
        fixture.Db.AdObjectSnapshots.Add(Snapshot(scan.Id, 50, RiskSeverity.High));
        fixture.Db.GroupMemberships.AddRange(
            Membership(scan.Id, "Backup Operators", 1, true, true, ["ivan", "Backup Operators"]),
            Membership(scan.Id, "Domain Admins", 3, false, true, ["ivan", "HelpDesk", "IT Administrators", "Domain Admins"]),
            Membership(scan.Id, "Domain Users", 1, true, false, ["ivan", "Domain Users"]));
        await fixture.Db.SaveChangesAsync();

        var model = (await fixture.Query.GetAsync(scan.Id, ObjectGuid))!;
        Assert.Equal(2, model.PrivilegeMemberships.Count);
        Assert.Equal(3, model.GroupMembershipCount);
        var direct = Assert.Single(model.PrivilegeMemberships, item => item.GroupName == "Backup Operators");
        Assert.True(direct.IsDirect);
        Assert.Equal(1, direct.Depth);
        var nested = Assert.Single(model.PrivilegeMemberships, item => item.GroupName == "Domain Admins");
        Assert.False(nested.IsDirect);
        Assert.Equal(3, nested.Depth);
        Assert.Equal(["ivan", "HelpDesk", "IT Administrators", "Domain Admins"], nested.PathDisplayNames);
        Assert.Contains(model.GroupMemberships, item => item.GroupName == "Domain Users" && !item.IsPrivileged);
    }

    [Fact]
    public async Task MalformedPathJsonReturnsFallbackButKeepsOtherSections()
    {
        await using var fixture = await Fixture.CreateAsync();
        var scan = await fixture.AddScanAsync();
        fixture.Db.AdObjectSnapshots.Add(Snapshot(scan.Id, 0, RiskSeverity.Low));
        fixture.Db.GroupMemberships.Add(Membership(scan.Id, "Admins", 1, true, true, null, "{broken"));
        await fixture.Db.SaveChangesAsync();
        var model = (await fixture.Query.GetAsync(scan.Id, ObjectGuid))!;
        Assert.False(Assert.Single(model.PrivilegeMemberships).PathAvailable);
        Assert.Empty(model.PrivilegeMemberships[0].PathDisplayNames);
        Assert.Equal(0, model.FindingsCount);
    }

    [Fact]
    public async Task DelegationTargetsAndMultipleMechanismsLoadFromSameScan()
    {
        await using var fixture = await Fixture.CreateAsync();
        var scan = await fixture.AddScanAsync();
        fixture.Db.AdObjectSnapshots.Add(Snapshot(scan.Id, 90, RiskSeverity.Critical));
        fixture.Db.DelegationRecords.AddRange(
            Delegation(scan.Id, DelegationType.Constrained, JsonSerializer.Serialize(new[] { "HTTP/app01", "MSSQLSvc/sql01" })),
            Delegation(scan.Id, DelegationType.Unconstrained, null),
            Delegation(scan.Id, DelegationType.ResourceBasedConstrained, "[]"));
        await fixture.Db.SaveChangesAsync();
        var model = (await fixture.Query.GetAsync(scan.Id, ObjectGuid))!;
        Assert.Equal(3, model.DelegationRecords.Count);
        var constrained = Assert.Single(model.DelegationRecords, item => item.DelegationType == DelegationType.Constrained);
        Assert.Equal(["HTTP/app01", "MSSQLSvc/sql01"], constrained.Targets);
        Assert.True(constrained.TargetsAvailable);
        Assert.Contains(model.DelegationRecords, item => item.DelegationType == DelegationType.Unconstrained);
        Assert.Contains(model.DelegationRecords, item => item.DelegationType == DelegationType.ResourceBasedConstrained);
    }

    [Fact]
    public async Task MalformedTargetsJsonDoesNotCrashHistoricalPage()
    {
        await using var fixture = await Fixture.CreateAsync();
        var scan = await fixture.AddScanAsync();
        fixture.Db.AdObjectSnapshots.Add(Snapshot(scan.Id, 0, RiskSeverity.Low));
        fixture.Db.DelegationRecords.Add(Delegation(scan.Id, DelegationType.Constrained, "{\"not\":\"an array\"}"));
        await fixture.Db.SaveChangesAsync();
        var model = (await fixture.Query.GetAsync(scan.Id, ObjectGuid))!;
        Assert.False(Assert.Single(model.DelegationRecords).TargetsAvailable);
        Assert.Empty(model.DelegationRecords[0].Targets);
    }

    [Fact]
    public async Task FindingsSortBySeverityPointsRuleIdAndTitle()
    {
        await using var fixture = await Fixture.CreateAsync();
        var scan = await fixture.AddScanAsync();
        fixture.Db.AdObjectSnapshots.Add(Snapshot(scan.Id, 100, RiskSeverity.Critical));
        fixture.Db.RiskFindings.AddRange(
            Finding(scan.Id, RiskSeverity.Low, 5, "LOW"),
            Finding(scan.Id, RiskSeverity.Critical, 30, "CRIT-B"),
            Finding(scan.Id, RiskSeverity.Critical, 50, "CRIT-A"),
            Finding(scan.Id, RiskSeverity.High, 25, "HIGH"),
            Finding(scan.Id, RiskSeverity.Medium, 15, "MEDIUM"));
        await fixture.Db.SaveChangesAsync();
        var model = (await fixture.Query.GetAsync(scan.Id, ObjectGuid))!;
        Assert.Equal(["CRIT-A", "CRIT-B", "HIGH", "MEDIUM", "LOW"],
            model.Findings.Select(item => item.RuleId));
        Assert.Equal(5, model.FindingsCount);
    }

    [Fact]
    public async Task BreakdownUsesSavedFindingsAndShowsCappedSnapshotScore()
    {
        await using var fixture = await Fixture.CreateAsync();
        var scan = await fixture.AddScanAsync();
        fixture.Db.AdObjectSnapshots.Add(Snapshot(scan.Id, 100, RiskSeverity.Critical));
        fixture.Db.RiskFindings.AddRange(Finding(scan.Id, RiskSeverity.Critical, 50, "A"),
            Finding(scan.Id, RiskSeverity.High, 50, "B"),
            Finding(scan.Id, RiskSeverity.Medium, 30, "C"));
        await fixture.Db.SaveChangesAsync();
        var model = (await fixture.Query.GetAsync(scan.Id, ObjectGuid))!;
        Assert.Equal(130, model.AccumulatedPoints);
        Assert.Equal(100, model.RiskScore);
        Assert.True(model.WasCapped);
    }

    [Fact]
    public async Task BreakdownBelowCapShowsAccumulatedNinetyFive()
    {
        await using var fixture = await Fixture.CreateAsync();
        var scan = await fixture.AddScanAsync();
        fixture.Db.AdObjectSnapshots.Add(Snapshot(scan.Id, 95, RiskSeverity.Critical));
        fixture.Db.RiskFindings.AddRange(Finding(scan.Id, RiskSeverity.Critical, 50, "A"),
            Finding(scan.Id, RiskSeverity.High, 30, "B"),
            Finding(scan.Id, RiskSeverity.Medium, 15, "C"));
        await fixture.Db.SaveChangesAsync();
        var model = (await fixture.Query.GetAsync(scan.Id, ObjectGuid))!;
        Assert.Equal(95, model.AccumulatedPoints);
        Assert.Equal(95, model.RiskScore);
        Assert.False(model.WasCapped);
    }

    [Fact]
    public async Task MissingScanObjectAndFailedScanWithoutSnapshotReturnNullAndController404()
    {
        await using var fixture = await Fixture.CreateAsync();
        var completed = await fixture.AddScanAsync();
        var failed = await fixture.AddScanAsync(ScanStatus.Failed);
        fixture.Db.AdObjectSnapshots.Add(Snapshot(completed.Id, 10, RiskSeverity.Low));
        await fixture.Db.SaveChangesAsync();
        Assert.Null(await fixture.Query.GetAsync(9999, ObjectGuid));
        Assert.Null(await fixture.Query.GetAsync(completed.Id, Guid.NewGuid()));
        Assert.Null(await fixture.Query.GetAsync(failed.Id, ObjectGuid));
        var controller = new ScanObjectsController(fixture.Query);
        Assert.IsType<NotFoundResult>(await controller.Details(9999, ObjectGuid));
        Assert.IsType<NotFoundResult>(await controller.Details(completed.Id, Guid.NewGuid()));
        Assert.IsType<NotFoundResult>(await controller.Details(failed.Id, ObjectGuid));
        var found = Assert.IsType<ViewResult>(await controller.Details(completed.Id, ObjectGuid));
        Assert.IsType<AccountDetailsViewModel>(found.Model);
    }

    [Fact]
    public async Task GroupMembershipsArePagedWithoutHidingPrivilegedPaths()
    {
        await using var fixture = await Fixture.CreateAsync();
        var scan = await fixture.AddScanAsync();
        fixture.Db.AdObjectSnapshots.Add(Snapshot(scan.Id, 0, RiskSeverity.Low));
        for (var index = 0; index < 53; index++)
            fixture.Db.GroupMemberships.Add(Membership(scan.Id, $"Group {index:00}", 1,
                true, index == 52, ["ivan", $"Group {index:00}"]));
        await fixture.Db.SaveChangesAsync();
        var first = (await fixture.Query.GetAsync(scan.Id, ObjectGuid))!;
        var second = (await fixture.Query.GetAsync(scan.Id, ObjectGuid, 2))!;
        Assert.Equal(53, first.GroupMembershipCount);
        Assert.Equal(2, first.MembershipPageCount);
        Assert.Equal(50, first.GroupMemberships.Count);
        Assert.Equal(3, second.GroupMemberships.Count);
        Assert.Equal("Group 52", Assert.Single(first.PrivilegeMemberships).GroupName);
    }

    private static AdObjectSnapshot Snapshot(long scanId, int riskScore, RiskSeverity level,
        bool? enabled = true, bool? locked = false, bool? expired = false) => new()
    {
        ScanRunId = scanId, ObjectGuid = ObjectGuid,
        SamAccountName = "ivan", DisplayName = "Ivan Petrov",
        DistinguishedName = "CN=Ivan Petrov,OU=Users,DC=adlab,DC=test",
        RiskScore = riskScore, RiskLevel = level,
        Enabled = enabled, Locked = locked, AccountExpired = expired
    };

    private static GroupMembership Membership(long scanId, string name, int depth,
        bool direct, bool privileged, string[]? path, string? rawPath = null) => new()
    {
        ScanRunId = scanId, PrincipalObjectGuid = ObjectGuid,
        GroupObjectGuid = Guid.NewGuid(), GroupName = name,
        GroupDistinguishedName = $"CN={name},OU=Groups,DC=adlab,DC=test",
        Depth = depth, IsDirect = direct, IsPrivileged = privileged,
        PathJson = rawPath ?? JsonSerializer.Serialize(path)
    };

    private static DelegationRecord Delegation(long scanId, DelegationType type, string? targetsJson) => new()
    {
        ScanRunId = scanId, ObjectGuid = ObjectGuid, ObjectName = "ivan",
        DelegationType = type, TargetsJson = targetsJson
    };

    private static RiskFinding Finding(long scanId, RiskSeverity severity, int points, string ruleId) => new()
    {
        ScanRunId = scanId, ObjectGuid = ObjectGuid,
        ObjectType = AdObjectType.User, ObjectName = "ivan",
        RuleId = ruleId, Category = "Test", Title = $"Finding {ruleId}",
        Description = "Description", Evidence = "Evidence",
        Recommendation = "Review", RiskPoints = points, Severity = severity
    };

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        public AppDbContext Db { get; }
        public ObjectDetailsQueryService Query { get; }

        private Fixture(SqliteConnection connection, AppDbContext db)
        {
            _connection = connection;
            Db = db;
            Query = new ObjectDetailsQueryService(db, NullLogger<ObjectDetailsQueryService>.Instance);
        }

        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.MigrateAsync();
            return new Fixture(connection, db);
        }

        public async Task<ScanRun> AddScanAsync(ScanStatus status = ScanStatus.Completed)
        {
            var scan = new ScanRun
            {
                StartedAtUtc = new DateTimeOffset(2026, 9, 24, 12, 0, 0, TimeSpan.Zero),
                FinishedAtUtc = new DateTimeOffset(2026, 9, 24, 12, 5, 0, TimeSpan.Zero),
                Status = status, Server = "dc01.adlab.test", BaseDn = "DC=adlab,DC=test"
            };
            Db.ScanRuns.Add(scan);
            await Db.SaveChangesAsync();
            return scan;
        }

        public async ValueTask DisposeAsync()
        { await Db.DisposeAsync(); await _connection.DisposeAsync(); }
    }
}

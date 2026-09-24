using System.Text.Json;
using IdentityRiskAnalyzer.Web.Controllers;
using IdentityRiskAnalyzer.Web.Data;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;
using IdentityRiskAnalyzer.Web.Services.Delegation;
using IdentityRiskAnalyzer.Web.Services.GroupAnalysis;
using IdentityRiskAnalyzer.Web.Services.RiskRules;
using IdentityRiskAnalyzer.Web.Services.Scanning;
using IdentityRiskAnalyzer.Web.Services.Scoring;
using IdentityRiskAnalyzer.Web.Services.SecurityEvents;
using IdentityRiskAnalyzer.Web.Services.Exchange;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Mvc;
using IdentityRiskAnalyzer.Web.ViewModels;

namespace IdentityRiskAnalyzer.Tests;

internal sealed class FakeEventCollector : ISecurityEventLogCollector
{
    public SecurityEventCollectionResult Result { get; set; } = new() { Status = SecurityEventCollectionStatus.Disabled };
    public int Calls { get; private set; }
    public SecurityEventCollectionResult Collect(CancellationToken cancellationToken) =>
        CollectCore(cancellationToken);
    private SecurityEventCollectionResult CollectCore(CancellationToken token)
    { Calls++; token.ThrowIfCancellationRequested(); return Result; }
}

public sealed class ActiveDirectoryScanServiceTests
{
    [Fact]
    public async Task DisabledEventFeatureDoesNotCallCollector()
    {
        await using var harness = await Harness.CreateAsync();
        harness.Ldap.Users = [User("alice")];
        var result = await harness.RunAsync([]);
        Assert.Equal(ScanStatus.Completed, result.Status);
        Assert.Equal(0, harness.Events.Calls);
    }

    [Fact]
    public async Task OptionalEventFailureKeepsDirectorySnapshotAndMarksErrors()
    {
        await using var harness = await Harness.CreateAsync();
        harness.Ldap.Users = [User("alice")];
        harness.EventOptions.Enabled = true;
        harness.Events.Result = new() { Status = SecurityEventCollectionStatus.Unavailable,
            ErrorMessage = "Security Event Log is unavailable." };
        var result = await harness.RunAsync([]);
        Assert.Equal(ScanStatus.CompletedWithErrors, result.Status);
        Assert.Equal(1, result.ErrorsCount);
        Assert.Equal(1, await harness.Db.AdObjectSnapshots.CountAsync());
        Assert.Equal(1, harness.Events.Calls);
    }

    [Fact]
    public async Task EnabledUnavailableExchangeInventoryIsRecoverable()
    {
        await using var harness = await Harness.CreateAsync();
        harness.Ldap.Users = [User("alice")];
        harness.ExchangeOptions.Enabled = true;
        var result = await harness.RunAsync([]);
        Assert.Equal(ScanStatus.CompletedWithErrors, result.Status);
        Assert.Equal(1, result.ErrorsCount);
        Assert.Equal(1, await harness.Db.AdObjectSnapshots.CountAsync());
    }

    [Fact]
    public async Task EventFindingIsPersistedAndIncludedInObjectScore()
    {
        await using var harness = await Harness.CreateAsync();
        var user = User("alice");
        harness.Ldap.Users = [user];
        harness.EventOptions.Enabled = true;
        var start = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        harness.Events.Result = new()
        {
            Status = SecurityEventCollectionStatus.Success,
            EventsRead = 10,
            Events = Enumerable.Range(0, 10).Select(index => new SecurityAuthenticationEvent
            {
                EventId = 4625, RecordId = index + 1, TimestampUtc = start.AddSeconds(index),
                TargetUserName = "ALICE", SourceIpAddress = "10.0.0.2"
            }).ToArray()
        };
        var result = await harness.RunAsync([]);
        Assert.Equal(ScanStatus.Completed, result.Status);
        Assert.Equal(1, result.FindingsCount);
        Assert.Equal(75, result.AdSecurityScore);
        Assert.Equal(25, (await harness.Db.AdObjectSnapshots.SingleAsync()).RiskScore);
        Assert.Equal(RiskRuleIds.PossibleBruteForce, (await harness.Db.RiskFindings.SingleAsync()).RuleId);
    }

    [Fact]
    public async Task SuccessfulScanPersistsAllSnapshotTypesAndUsesScoredFindings()
    {
        await using var harness = await Harness.CreateAsync();
        var user = User("ivan");
        var helpDesk = Group("HelpDesk", [user.DistinguishedName]);
        var admins = Group("Domain Admins", [helpDesk.DistinguishedName], "S-1-5-21-1-2-3-512");
        harness.Ldap.Users = [user];
        harness.Ldap.Groups = [helpDesk, admins];

        var result = await harness.RunAsync([new FixedFindingRule()]);

        Assert.Equal(ScanStatus.Completed, result.Status);
        Assert.Equal(1, result.ObjectsScanned);
        Assert.Equal(1, result.FindingsCount);
        Assert.Equal(70, result.AdSecurityScore);
        Assert.Equal(1, harness.Ldap.UsersCalls);
        Assert.Equal(1, harness.Ldap.ManagedCalls);
        Assert.Equal(1, harness.Ldap.GroupsCalls);
        var run = await harness.Db.ScanRuns.SingleAsync();
        Assert.NotNull(run.FinishedAtUtc);
        var snapshot = await harness.Db.AdObjectSnapshots.SingleAsync();
        Assert.True(snapshot.IsPrivileged);
        Assert.Equal(30, snapshot.RiskScore);
        Assert.Equal(AdObjectType.User, snapshot.ObjectType);
        Assert.Equal(2, await harness.Db.GroupMemberships.CountAsync());
        var nested = await harness.Db.GroupMemberships.SingleAsync(item => item.GroupName == "Domain Admins");
        Assert.True(nested.IsPrivileged);
        Assert.False(nested.IsDirect);
        Assert.Equal(2, nested.Depth);
        Assert.Equal(["ivan", "HelpDesk", "Domain Admins"], JsonSerializer.Deserialize<string[]>(nested.PathJson)!);
        var delegation = await harness.Db.DelegationRecords.SingleAsync();
        Assert.Equal(DelegationType.Constrained, delegation.DelegationType);
        Assert.Equal(["HTTP/app01"], JsonSerializer.Deserialize<string[]>(delegation.TargetsJson!)!);
        var finding = await harness.Db.RiskFindings.SingleAsync();
        Assert.Equal("IRA-TEST-001", finding.RuleId);
        Assert.Equal(30, finding.RiskPoints);
    }

    [Fact]
    public async Task TwoScansKeepSeparateHistoricalSnapshots()
    {
        await using var harness = await Harness.CreateAsync();
        harness.Ldap.Users = [User("first")];
        var first = await harness.RunAsync([new FixedFindingRule()]);
        harness.Ldap.Users = [User("second")];
        var second = await harness.RunAsync([]);

        Assert.NotEqual(first.ScanRunId, second.ScanRunId);
        Assert.Equal(2, await harness.Db.ScanRuns.CountAsync());
        Assert.Equal(30, (await harness.Db.AdObjectSnapshots.SingleAsync(item => item.ScanRunId == first.ScanRunId)).RiskScore);
        Assert.Equal(0, (await harness.Db.AdObjectSnapshots.SingleAsync(item => item.ScanRunId == second.ScanRunId)).RiskScore);
        Assert.Equal(1, await harness.Db.RiskFindings.CountAsync(item => item.ScanRunId == first.ScanRunId));
        Assert.Equal(0, await harness.Db.RiskFindings.CountAsync(item => item.ScanRunId == second.ScanRunId));
        Assert.Equal(100, second.AdSecurityScore);
    }

    [Fact]
    public async Task FatalLdapFailureLeavesFailedRunWithoutSecrets()
    {
        await using var harness = await Harness.CreateAsync();
        harness.Ldap.UsersFailure = new InvalidOperationException("secret-password-in-exception");
        var result = await harness.RunAsync([]);

        Assert.Equal(ScanStatus.Failed, result.Status);
        var run = await harness.Db.ScanRuns.SingleAsync();
        Assert.NotNull(run.FinishedAtUtc);
        Assert.DoesNotContain("secret-password", run.ErrorMessage!);
        Assert.Empty(await harness.Db.AdObjectSnapshots.ToListAsync());
    }

    [Fact]
    public async Task OneMalformedPrincipalCompletesWithErrorsAndKeepsHealthyPrincipal()
    {
        await using var harness = await Harness.CreateAsync();
        harness.Ldap.Users = [new AdUserRecord
        {
            ObjectGuid = Guid.NewGuid(), SamAccountName = "bad",
            DistinguishedName = "CN=bad,OU=Users,DC=adlab,DC=test",
            ObjectClasses = null!
        }, User("good")];
        var result = await harness.RunAsync([]);

        Assert.Equal(ScanStatus.CompletedWithErrors, result.Status);
        Assert.Equal(1, result.ObjectsScanned);
        Assert.True(result.ErrorsCount >= 1);
        Assert.Equal("good", (await harness.Db.AdObjectSnapshots.SingleAsync()).SamAccountName);
    }

    [Fact]
    public async Task RuleFailureIsCountedButOtherRulesStillPersist()
    {
        await using var harness = await Harness.CreateAsync();
        harness.Ldap.Users = [User("ivan")];
        var result = await harness.RunAsync([new ThrowingRule(), new FixedFindingRule()]);

        Assert.Equal(ScanStatus.CompletedWithErrors, result.Status);
        Assert.Equal(1, result.ErrorsCount);
        Assert.Equal(1, result.FindingsCount);
        Assert.Single(await harness.Db.RiskFindings.ToListAsync());
    }

    [Fact]
    public async Task FinalPersistenceFailureRollsBackSnapshotAndMarksRunFailed()
    {
        await using var harness = await Harness.CreateAsync();
        harness.Ldap.Users = [User("ivan")];
        await harness.Db.Database.ExecuteSqlRawAsync(
            "CREATE TRIGGER reject_findings BEFORE INSERT ON RiskFindings BEGIN SELECT RAISE(ABORT, 'test failure'); END;");
        var result = await harness.RunAsync([new FixedFindingRule()]);

        Assert.Equal(ScanStatus.Failed, result.Status);
        Assert.Empty(await harness.Db.AdObjectSnapshots.ToListAsync());
        Assert.Empty(await harness.Db.GroupMemberships.ToListAsync());
        Assert.Empty(await harness.Db.RiskFindings.ToListAsync());
        var run = await harness.Db.ScanRuns.SingleAsync();
        Assert.Equal(ScanStatus.Failed, run.Status);
        Assert.NotNull(run.FinishedAtUtc);
    }

    [Fact]
    public async Task CancellationAfterRunCreationMarksItCancelled()
    {
        await using var harness = await Harness.CreateAsync();
        using var cts = new CancellationTokenSource();
        harness.Ldap.OnGetUsers = () => cts.Cancel();
        var result = await harness.RunAsync([], cts.Token);

        Assert.Equal(ScanStatus.Cancelled, result.Status);
        var run = await harness.Db.ScanRuns.SingleAsync();
        Assert.Equal(ScanStatus.Cancelled, run.Status);
        Assert.NotNull(run.FinishedAtUtc);
    }

    [Fact]
    public async Task EmptyDirectoryHasNullSecurityScore()
    {
        await using var harness = await Harness.CreateAsync();
        var result = await harness.RunAsync([]);
        Assert.Equal(ScanStatus.Completed, result.Status);
        Assert.Equal(0, result.ObjectsScanned);
        Assert.Null(result.AdSecurityScore);
        Assert.Empty(await harness.Db.AdObjectSnapshots.ToListAsync());
    }

    [Fact]
    public async Task RunningScanGateRejectsSecondStartWithoutCreatingRow()
    {
        await using var harness = await Harness.CreateAsync();
        using var activeScan = harness.Gate.TryEnter();
        Assert.NotNull(activeScan);
        var result = await harness.RunAsync([]);
        Assert.True(result.AlreadyRunning);
        Assert.Equal(ScanStatus.Running, result.Status);
        Assert.Empty(await harness.Db.ScanRuns.ToListAsync());
    }

    [Fact]
    public async Task IncompleteGroupMembershipSetsCompletedWithErrors()
    {
        await using var harness = await Harness.CreateAsync();
        harness.Ldap.Users = [User("ivan")];
        harness.Ldap.Groups = [new AdGroupRecord
        {
            ObjectGuid = Guid.NewGuid(), DistinguishedName = "CN=Incomplete,DC=adlab,DC=test",
            CommonName = "Incomplete", MembersComplete = false
        }];
        var result = await harness.RunAsync([]);
        Assert.Equal(ScanStatus.CompletedWithErrors, result.Status);
        Assert.Equal(1, result.ErrorsCount);
        Assert.Equal(1, result.ObjectsScanned);
    }

    [Fact]
    public async Task ManagedAccountCollectedOnceAndDuplicateGuidDoesNotCreateSecondSnapshot()
    {
        await using var harness = await Harness.CreateAsync();
        var user = User("svc_one", ["user", "msDS-ManagedServiceAccount"]);
        harness.Ldap.Users = [user];
        harness.Ldap.Managed = [user];
        var result = await harness.RunAsync([]);
        Assert.Equal(ScanStatus.Completed, result.Status);
        Assert.Equal(1, result.ObjectsScanned);
        Assert.Equal(1, await harness.Db.AdObjectSnapshots.CountAsync());
        Assert.Equal(AdObjectType.ServiceAccount, (await harness.Db.AdObjectSnapshots.SingleAsync()).ObjectType);
        Assert.Equal(1, harness.Ldap.ManagedCalls);
    }

    [Fact]
    public async Task ScanDetailsReadsPersistedSummaryWithoutCallingLdap()
    {
        await using var harness = await Harness.CreateAsync();
        harness.Ldap.Users = [User("ivan")];
        var run = await harness.RunAsync([new FixedFindingRule()]);
        var controller = new ScansController(harness.Db, new UnavailableScanService());

        var action = await controller.Details(run.ScanRunId, CancellationToken.None);
        var view = Assert.IsType<ViewResult>(action);
        var model = Assert.IsType<ScanDetailsViewModel>(view.Model);
        Assert.Equal(ScanStatus.Completed, model.Summary.Status);
        Assert.Equal(1, model.FindingSeverityCounts[RiskSeverity.Medium]);
        Assert.Equal(1, model.ObjectRiskCounts[RiskSeverity.Medium]);
        Assert.Equal("ivan", Assert.Single(model.TopRiskyAccounts).Name);
        Assert.Equal("IRA-TEST-001", Assert.Single(model.Findings).RuleId);
    }

    private static AdUserRecord User(string name, IReadOnlyList<string>? objectClasses = null) => new()
    {
        ObjectGuid = Guid.NewGuid(), SamAccountName = name,
        DistinguishedName = $"CN={name},OU=Users,DC=adlab,DC=test",
        ObjectClasses = objectClasses ?? ["user"], AllowedToDelegateTo = name == "ivan" ? ["HTTP/app01"] : []
    };

    private static AdGroupRecord Group(string name, IReadOnlyList<string> members, string? sid = null) => new()
    {
        ObjectGuid = Guid.NewGuid(), CommonName = name, Sid = sid,
        DistinguishedName = $"CN={name},OU=Groups,DC=adlab,DC=test",
        MemberDistinguishedNames = members
    };

    private sealed class FixedFindingRule : IAdRiskRule
    {
        public string RuleId => "IRA-TEST-001";
        public string Category => "Test";
        public IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context) =>
        [new() { ObjectGuid = context.User.ObjectGuid, ObjectType = context.ObjectType,
            ObjectName = context.ObjectName, RuleId = RuleId, Category = Category,
            Title = "Test finding", Description = "Test description", Evidence = "test evidence",
            Recommendation = "Review", RiskPoints = 30, Severity = RiskSeverity.Medium }];
    }

    private sealed class ThrowingRule : IAdRiskRule
    {
        public string RuleId => "IRA-TEST-FAIL";
        public string Category => "Test";
        public IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context) =>
            throw new InvalidOperationException("Test rule failure");
    }

    private sealed class FakeLdap : IActiveDirectoryClient
    {
        public IReadOnlyList<AdUserRecord> Users { get; set; } = [];
        public IReadOnlyList<AdUserRecord> Managed { get; set; } = [];
        public IReadOnlyList<AdGroupRecord> Groups { get; set; } = [];
        public Exception? UsersFailure { get; set; }
        public Action? OnGetUsers { get; set; }
        public int UsersCalls { get; private set; }
        public int ManagedCalls { get; private set; }
        public int GroupsCalls { get; private set; }
        public LdapConnectionTestResult TestConnection(CancellationToken token) => throw new NotSupportedException();
        public IReadOnlyList<AdUserRecord> GetUsers(CancellationToken token)
        {
            UsersCalls++;
            OnGetUsers?.Invoke();
            token.ThrowIfCancellationRequested();
            if (UsersFailure is not null) throw UsersFailure;
            return Users;
        }
        public IReadOnlyList<AdUserRecord> GetManagedServiceAccounts(CancellationToken token)
        { ManagedCalls++; token.ThrowIfCancellationRequested(); return Managed; }
        public IReadOnlyList<AdGroupRecord> GetGroups(CancellationToken token)
        { GroupsCalls++; token.ThrowIfCancellationRequested(); return Groups; }
    }

    private sealed class UnavailableScanService : IActiveDirectoryScanService
    {
        public Task<ScanExecutionResult> RunScanAsync(CancellationToken token) =>
            throw new InvalidOperationException("Historical details must not start a scan.");
    }

    private sealed class Harness : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly ScanConcurrencyGate _gate = new();
        public AppDbContext Db { get; }
        public FakeLdap Ldap { get; } = new();
        public FakeEventCollector Events { get; } = new();
        public SecurityEventLogOptions EventOptions { get; } = new();
        public ExchangeDelegationOptions ExchangeOptions { get; } = new();
        public ScanConcurrencyGate Gate => _gate;

        private Harness(SqliteConnection connection, AppDbContext db)
        { _connection = connection; Db = db; }

        public static async Task<Harness> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.MigrateAsync();
            return new Harness(connection, db);
        }

        public Task<ScanExecutionResult> RunAsync(IReadOnlyCollection<IAdRiskRule> rules, CancellationToken token = default)
        {
            var adOptions = Options.Create(new ActiveDirectoryOptions { Server = "dc01.adlab.test", BaseDn = "DC=adlab,DC=test" });
            var riskOptions = Options.Create(new RiskSettings());
            var service = new ActiveDirectoryScanService(
                Db, Ldap,
                new GroupGraphService(NullLogger<GroupGraphService>.Instance, Options.Create(new GroupAnalysisOptions())),
                new PrivilegedGroupAnalyzer(NullLogger<PrivilegedGroupAnalyzer>.Instance,
                    Options.Create(new PrivilegeAnalysisOptions { PrivilegedGroups = [new() { Name = "Domain Admins", Rid = 512 }] })),
                new ServiceAccountClassifier(NullLogger<ServiceAccountClassifier>.Instance, Options.Create(new ServiceAccountAnalysisOptions())),
                new DelegationAnalyzer(NullLogger<DelegationAnalyzer>.Instance), new DuplicateSpnAnalyzer(),
                new RiskEngine(rules, NullLogger<RiskEngine>.Instance),
                new RiskScoringService(riskOptions, NullLogger<RiskScoringService>.Instance),
                Events, new AuthenticationThreatAnalyzer(Options.Create(EventOptions)),
                Options.Create(EventOptions),
                new UnavailableExchangeDelegationCollector(Options.Create(ExchangeOptions)),
                adOptions, riskOptions, TimeProvider.System, _gate, NullLogger<ActiveDirectoryScanService>.Instance);
            return service.RunScanAsync(token);
        }

        public async ValueTask DisposeAsync()
        { await Db.DisposeAsync(); await _connection.DisposeAsync(); _gate.Dispose(); }
    }
}

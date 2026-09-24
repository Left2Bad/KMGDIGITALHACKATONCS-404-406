using System.Text;
using IdentityRiskAnalyzer.Web.Controllers;
using IdentityRiskAnalyzer.Web.Data;
using IdentityRiskAnalyzer.Web.Domain.Entities;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Services.Export;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualBasic.FileIO;

namespace IdentityRiskAnalyzer.Tests;

public sealed class CsvExportServiceTests
{
    private static readonly Guid GuidA = Guid.Parse("b773db75-c146-42ae-a763-131711211a01");
    private static readonly Guid GuidB = Guid.Parse("b773db75-c146-42ae-a763-131711211a02");

    [Fact]
    public async Task AccountsCsvContainsSavedFieldsAndAggregatedFindingCounts()
    {
        await using var fixture = await Fixture.CreateAsync();
        var scan = await fixture.AddScanAsync(ScanStatus.CompletedWithErrors);
        fixture.Db.AdObjectSnapshots.AddRange(
            Account(scan.Id, GuidA, "=HYPERLINK(\"x\")", 90, RiskSeverity.Critical, privileged: true),
            Account(scan.Id, GuidB, "Обычный; сервис", 10, RiskSeverity.Low, service: true));
        fixture.Db.RiskFindings.AddRange(
            Finding(scan.Id, GuidA, RiskSeverity.Critical, 50, "A"),
            Finding(scan.Id, GuidA, RiskSeverity.High, 30, "B"),
            Finding(scan.Id, GuidA, RiskSeverity.Medium, 10, "C"));
        await fixture.Db.SaveChangesAsync();

        var file = (await fixture.Export.ExportAccountsAsync(scan.Id))!;
        var rows = Parse(file.Content);
        Assert.Equal(2, file.Rows);
        Assert.Equal(3, rows.Count);
        Assert.Equal("ScanId", rows[0][0]);
        Assert.Equal("FindingsCount", rows[0][^1]);
        Assert.Equal(scan.Id.ToString(), rows[1][0]);
        Assert.Equal("CompletedWithErrors", rows[1][1]);
        Assert.Equal("2026-09-24T12:00:00Z", rows[1][2]);
        Assert.Equal("'=HYPERLINK(\"x\")", rows[1][7]);
        Assert.Equal("", rows[1][11]); // Unknown Enabled remains empty.
        Assert.Equal("false", rows[1][12]);
        Assert.Equal("true", rows[1][15]);
        Assert.Equal("90", rows[1][19]);
        Assert.Equal("Critical", rows[1][20]);
        Assert.Equal("3", rows[1][21]);
        Assert.Equal("Обычный; сервис", rows[2][7]);
        Assert.Equal("true", rows[2][14]);
        Assert.Equal("0", rows[2][21]);
        Assert.StartsWith("identity-risk-scan-", file.FileName);
        Assert.EndsWith("-accounts.csv", file.FileName);
        Assert.Contains(scan.Id.ToString(), file.FileName);
        Assert.Equal([0xEF, 0xBB, 0xBF], file.Content[..3]);
    }

    [Fact]
    public async Task FindingsCsvPreservesEvidenceRecommendationAndSavedObjectScore()
    {
        await using var fixture = await Fixture.CreateAsync();
        var scan = await fixture.AddScanAsync();
        fixture.Db.AdObjectSnapshots.AddRange(Account(scan.Id, GuidA, "Alpha", 95, RiskSeverity.Critical),
            Account(scan.Id, GuidB, "Beta", 25, RiskSeverity.Medium));
        var critical = Finding(scan.Id, GuidA, RiskSeverity.Critical, 50, "CRITICAL");
        critical.Evidence = "Line 1\r\nLine 2";
        critical.Recommendation = "Проверить владельца; затем согласовать удаление.";
        critical.ObjectName = "+Admin";
        fixture.Db.RiskFindings.AddRange(
            Finding(scan.Id, GuidB, RiskSeverity.Low, 5, "LOW"),
            Finding(scan.Id, GuidA, RiskSeverity.High, 30, "HIGH"),
            critical,
            Finding(scan.Id, GuidB, RiskSeverity.Medium, 15, "MEDIUM"));
        await fixture.Db.SaveChangesAsync();

        var file = (await fixture.Export.ExportFindingsAsync(scan.Id))!;
        var rows = Parse(file.Content);
        Assert.Equal(4, file.Rows);
        Assert.Equal(["Critical", "High", "Medium", "Low"], rows.Skip(1).Select(row => row[8]));
        Assert.Equal("'+Admin", rows[1][5]);
        Assert.Equal("CRITICAL", rows[1][6]);
        Assert.Equal("50", rows[1][9]);
        Assert.Equal("Line 1\r\nLine 2", rows[1][12]);
        Assert.Equal("Проверить владельца; затем согласовать удаление.", rows[1][13]);
        Assert.Equal("95", rows[1][14]);
        Assert.Equal("Critical", rows[1][15]);
        Assert.Equal("25", rows[3][14]);
        Assert.EndsWith("-findings.csv", file.FileName);
    }

    [Fact]
    public async Task ExportsUseOnlyRequestedScanForSameObjectGuid()
    {
        await using var fixture = await Fixture.CreateAsync();
        var first = await fixture.AddScanAsync();
        var second = await fixture.AddScanAsync();
        fixture.Db.AdObjectSnapshots.AddRange(Account(first.Id, GuidA, "Ivan", 90, RiskSeverity.Critical),
            Account(second.Id, GuidA, "Ivan", 10, RiskSeverity.Low));
        fixture.Db.RiskFindings.AddRange(Finding(first.Id, GuidA, RiskSeverity.Critical, 50, "OLD"),
            Finding(second.Id, GuidA, RiskSeverity.Low, 5, "NEW"));
        await fixture.Db.SaveChangesAsync();

        var accounts = Parse((await fixture.Export.ExportAccountsAsync(first.Id))!.Content);
        var findings = Parse((await fixture.Export.ExportFindingsAsync(first.Id))!.Content);
        Assert.Equal(2, accounts.Count);
        Assert.Equal("90", accounts[1][19]);
        Assert.Equal("1", accounts[1][21]);
        Assert.Equal(2, findings.Count);
        Assert.Equal("OLD", findings[1][6]);
        Assert.Equal("90", findings[1][14]);
    }

    [Fact]
    public async Task EmptyCompletedScanExportsHeaderOnly()
    {
        await using var fixture = await Fixture.CreateAsync();
        var scan = await fixture.AddScanAsync();
        var accounts = (await fixture.Export.ExportAccountsAsync(scan.Id))!;
        var findings = (await fixture.Export.ExportFindingsAsync(scan.Id))!;
        Assert.Equal(0, accounts.Rows);
        Assert.Equal(0, findings.Rows);
        Assert.Single(Parse(accounts.Content));
        Assert.Single(Parse(findings.Content));
    }

    [Theory]
    [InlineData(ScanStatus.Failed)]
    [InlineData(ScanStatus.Running)]
    [InlineData(ScanStatus.Cancelled)]
    [InlineData(ScanStatus.Pending)]
    public async Task NonExportableStatusesReturnNoFile(ScanStatus status)
    {
        await using var fixture = await Fixture.CreateAsync();
        var scan = await fixture.AddScanAsync(status);
        Assert.Null(await fixture.Export.ExportAccountsAsync(scan.Id));
        Assert.Null(await fixture.Export.ExportFindingsAsync(scan.Id));
        var controller = new ScanExportsController(fixture.Export);
        Assert.IsType<NotFoundObjectResult>(await controller.Accounts(scan.Id, CancellationToken.None));
        Assert.IsType<NotFoundObjectResult>(await controller.Findings(scan.Id, CancellationToken.None));
    }

    [Fact]
    public async Task MissingScanReturnsController404()
    {
        await using var fixture = await Fixture.CreateAsync();
        var controller = new ScanExportsController(fixture.Export);
        Assert.IsType<NotFoundObjectResult>(await controller.Accounts(9999, CancellationToken.None));
        Assert.IsType<NotFoundObjectResult>(await controller.Findings(9999, CancellationToken.None));
    }

    [Fact]
    public async Task SuccessfulControllerReturnsCsvFileWithUtf8ContentTypeAndSafeFilename()
    {
        await using var fixture = await Fixture.CreateAsync();
        var scan = await fixture.AddScanAsync();
        var controller = new ScanExportsController(fixture.Export);
        var accountFile = Assert.IsType<FileContentResult>(await controller.Accounts(scan.Id, CancellationToken.None));
        var findingFile = Assert.IsType<FileContentResult>(await controller.Findings(scan.Id, CancellationToken.None));
        Assert.Equal("text/csv; charset=utf-8", accountFile.ContentType);
        Assert.Equal("text/csv; charset=utf-8", findingFile.ContentType);
        Assert.Equal($"identity-risk-scan-{scan.Id}-accounts.csv", accountFile.FileDownloadName);
        Assert.Equal($"identity-risk-scan-{scan.Id}-findings.csv", findingFile.FileDownloadName);
        Assert.Equal([0xEF, 0xBB, 0xBF], accountFile.FileContents[..3]);
    }

    private static List<string[]> Parse(byte[] bytes)
    {
        using var parser = new TextFieldParser(new MemoryStream(bytes), Encoding.UTF8, true);
        parser.TextFieldType = FieldType.Delimited;
        parser.SetDelimiters(";");
        parser.HasFieldsEnclosedInQuotes = true;
        var rows = new List<string[]>();
        while (!parser.EndOfData) rows.Add(parser.ReadFields()!);
        return rows;
    }

    private static AdObjectSnapshot Account(long scanId, Guid objectGuid, string displayName,
        int score, RiskSeverity level, bool privileged = false, bool service = false) => new()
    {
        ScanRunId = scanId, ObjectGuid = objectGuid, ObjectType = AdObjectType.User,
        SamAccountName = objectGuid == GuidA ? "ivan" : "service",
        DisplayName = displayName, DistinguishedName = $"CN={displayName},DC=adlab,DC=test",
        Enabled = null, Locked = false, AccountExpired = false,
        IsServiceAccount = service, IsPrivileged = privileged,
        RiskScore = score, RiskLevel = level
    };

    private static RiskFinding Finding(long scanId, Guid objectGuid, RiskSeverity severity,
        int points, string ruleId) => new()
    {
        ScanRunId = scanId, ObjectGuid = objectGuid, ObjectType = AdObjectType.User,
        ObjectName = "ivan", RuleId = ruleId, Category = "Test", Title = "Finding",
        Description = "Description", Evidence = "Evidence", Recommendation = "Review",
        Severity = severity, RiskPoints = points
    };

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        public AppDbContext Db { get; }
        public CsvExportService Export { get; }

        private Fixture(SqliteConnection connection, AppDbContext db)
        {
            _connection = connection;
            Db = db;
            Export = new CsvExportService(db, NullLogger<CsvExportService>.Instance);
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

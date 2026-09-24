using System.Diagnostics;
using System.Globalization;
using IdentityRiskAnalyzer.Web.Data;
using IdentityRiskAnalyzer.Web.Domain.Entities;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IdentityRiskAnalyzer.Web.Services.Export;

public sealed class CsvExportService(AppDbContext db, ILogger<CsvExportService> logger)
{
    private static readonly string[] AccountColumns =
    [
        "ScanId", "ScanStatus", "ScanStartedUtc", "ScanFinishedUtc",
        "ObjectGuid", "ObjectType", "SamAccountName", "DisplayName", "UserPrincipalName",
        "DistinguishedName", "Sid", "Enabled", "Locked", "AccountExpired",
        "IsServiceAccount", "IsPrivileged", "LastKnownActivityUtc", "PasswordLastSetUtc",
        "PasswordNeverExpires", "RiskScore", "RiskLevel", "FindingsCount"
    ];

    private static readonly string[] FindingColumns =
    [
        "ScanId", "ScanStatus", "ScanStartedUtc", "ObjectGuid", "ObjectType", "ObjectName",
        "RuleId", "Category", "Severity", "RiskPoints", "Title", "Description", "Evidence",
        "Recommendation", "ObjectRiskScore", "ObjectRiskLevel"
    ];

    public async Task<CsvExportFile?> ExportAccountsAsync(long scanId, CancellationToken cancellationToken = default)
    {
        var timer = Stopwatch.StartNew();
        var scan = await GetExportableScanAsync(scanId, cancellationToken);
        if (scan is null) return null;

        var snapshots = await db.AdObjectSnapshots.AsNoTracking()
            .Where(item => item.ScanRunId == scanId)
            .OrderByDescending(item => item.RiskScore)
            .ThenByDescending(item => item.RiskLevel)
            .ThenBy(item => item.SamAccountName)
            .ThenBy(item => item.ObjectGuid)
            .ToListAsync(cancellationToken);
        var findingCounts = await db.RiskFindings.AsNoTracking()
            .Where(item => item.ScanRunId == scanId)
            .GroupBy(item => item.ObjectGuid)
            .Select(group => new { ObjectGuid = group.Key, Count = group.Count() })
            .ToDictionaryAsync(item => item.ObjectGuid, item => item.Count, cancellationToken);

        var writer = new CsvWriter();
        writer.WriteRow(AccountColumns.Select(CsvField.Text).ToArray());
        foreach (var account in snapshots)
        {
            cancellationToken.ThrowIfCancellationRequested();
            writer.WriteRow(
                CsvField.Number(scan.Id), CsvField.Text(scan.Status.ToString()),
                CsvField.Timestamp(scan.StartedAtUtc), CsvField.Timestamp(scan.FinishedAtUtc),
                CsvField.Text(account.ObjectGuid.ToString("D")), CsvField.Text(account.ObjectType.ToString()),
                CsvField.Text(account.SamAccountName), CsvField.Text(account.DisplayName),
                CsvField.Text(account.UserPrincipalName), CsvField.Text(account.DistinguishedName),
                CsvField.Text(account.Sid), CsvField.Boolean(account.Enabled), CsvField.Boolean(account.Locked),
                CsvField.Boolean(account.AccountExpired), CsvField.Boolean(account.IsServiceAccount),
                CsvField.Boolean(account.IsPrivileged), CsvField.Timestamp(account.LastKnownActivityUtc),
                CsvField.Timestamp(account.PasswordLastSetUtc), CsvField.Boolean(account.PasswordNeverExpires),
                CsvField.Number(account.RiskScore), CsvField.Text(account.RiskLevel.ToString()),
                CsvField.Number(findingCounts.GetValueOrDefault(account.ObjectGuid)));
        }

        logger.LogInformation("CSV export generated for scan {ScanRunId}, type Accounts, {Rows} rows in {DurationMs} ms.",
            scanId, snapshots.Count, timer.ElapsedMilliseconds);
        return new CsvExportFile(writer.ToArray(), FileName(scanId, "accounts"), snapshots.Count);
    }

    public async Task<CsvExportFile?> ExportFindingsAsync(long scanId, CancellationToken cancellationToken = default)
    {
        var timer = Stopwatch.StartNew();
        var scan = await GetExportableScanAsync(scanId, cancellationToken);
        if (scan is null) return null;

        var scoreByObject = await db.AdObjectSnapshots.AsNoTracking()
            .Where(item => item.ScanRunId == scanId)
            .Select(item => new { item.ObjectGuid, item.RiskScore, item.RiskLevel })
            .ToDictionaryAsync(item => item.ObjectGuid, cancellationToken);
        var findings = await db.RiskFindings.AsNoTracking()
            .Where(item => item.ScanRunId == scanId)
            .ToListAsync(cancellationToken);
        var sorted = findings
            .OrderByDescending(item => item.Severity)
            .ThenByDescending(item => item.RiskPoints)
            .ThenByDescending(item => scoreByObject.TryGetValue(item.ObjectGuid, out var score) ? score.RiskScore : -1)
            .ThenBy(item => item.ObjectName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.RuleId, StringComparer.Ordinal)
            .ThenBy(item => item.ObjectGuid)
            .ThenBy(item => item.Id)
            .ToArray();

        var writer = new CsvWriter();
        writer.WriteRow(FindingColumns.Select(CsvField.Text).ToArray());
        foreach (var finding in sorted)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var hasScore = scoreByObject.TryGetValue(finding.ObjectGuid, out var account);
            writer.WriteRow(
                CsvField.Number(scan.Id), CsvField.Text(scan.Status.ToString()),
                CsvField.Timestamp(scan.StartedAtUtc), CsvField.Text(finding.ObjectGuid.ToString("D")),
                CsvField.Text(finding.ObjectType.ToString()), CsvField.Text(finding.ObjectName),
                CsvField.Text(finding.RuleId), CsvField.Text(finding.Category),
                CsvField.Text(finding.Severity.ToString()), CsvField.Number(finding.RiskPoints),
                CsvField.Text(finding.Title), CsvField.Text(finding.Description),
                CsvField.Text(finding.Evidence), CsvField.Text(finding.Recommendation),
                hasScore ? CsvField.Number(account!.RiskScore) : CsvField.Text(null),
                CsvField.Text(hasScore ? account!.RiskLevel.ToString() : null));
        }

        logger.LogInformation("CSV export generated for scan {ScanRunId}, type Findings, {Rows} rows in {DurationMs} ms.",
            scanId, sorted.Length, timer.ElapsedMilliseconds);
        return new CsvExportFile(writer.ToArray(), FileName(scanId, "findings"), sorted.Length);
    }

    private async Task<ScanRun?> GetExportableScanAsync(long scanId, CancellationToken cancellationToken) =>
        await db.ScanRuns.AsNoTracking().Where(item => item.Id == scanId &&
            (item.Status == ScanStatus.Completed || item.Status == ScanStatus.CompletedWithErrors))
            .SingleOrDefaultAsync(cancellationToken);

    private static string FileName(long scanId, string kind) =>
        $"identity-risk-scan-{scanId.ToString(CultureInfo.InvariantCulture)}-{kind}.csv";
}

using IdentityRiskAnalyzer.Web.Data;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Services.RiskRules;
using IdentityRiskAnalyzer.Web.ViewModels;
using Microsoft.EntityFrameworkCore;

namespace IdentityRiskAnalyzer.Web.Services.Dashboard;

// Reads one historical SQLite snapshot. It deliberately has no LDAP dependency.
public sealed class DashboardQueryService(AppDbContext db)
{
    private const int ListLimit = 10;

    public async Task<DashboardViewModel> GetDashboardAsync(CancellationToken cancellationToken = default)
    {
        var latestCompleted = await db.ScanRuns.AsNoTracking()
            .Where(run => run.Status == ScanStatus.Completed || run.Status == ScanStatus.CompletedWithErrors)
            // Scan IDs follow creation order; SQLite cannot ORDER BY DateTimeOffset.
            .OrderByDescending(run => run.Id)
            .Select(run => new { run.Id, run.StartedAtUtc, run.FinishedAtUtc, run.Status,
                run.Server, run.BaseDn, run.AdSecurityScore, run.ObjectsScanned,
                run.FindingsCount, run.ErrorsCount })
            .FirstOrDefaultAsync(cancellationToken);

        var lastUsableId = latestCompleted?.Id ?? 0;
        var latestFailed = await db.ScanRuns.AsNoTracking()
            .Where(run => run.Status == ScanStatus.Failed
                && run.Id > lastUsableId)
            .OrderByDescending(run => run.Id)
            .Select(run => new DashboardFailedScanViewModel
            {
                ScanRunId = run.Id, StartedAtUtc = run.StartedAtUtc,
                FinishedAtUtc = run.FinishedAtUtc, ErrorMessage = run.ErrorMessage
            }).FirstOrDefaultAsync(cancellationToken);
        var scanRunning = await db.ScanRuns.AsNoTracking()
            .AnyAsync(run => run.Status == ScanStatus.Running, cancellationToken);

        if (latestCompleted is null)
        {
            return new DashboardViewModel { LatestFailedScan = latestFailed, ScanRunning = scanRunning };
        }

        var scanId = latestCompleted.Id;
        var findingCounts = await db.RiskFindings.AsNoTracking().Where(item => item.ScanRunId == scanId)
            .GroupBy(item => item.Severity)
            .Select(group => new { Severity = group.Key, Count = group.Count() })
            .ToDictionaryAsync(item => item.Severity, item => item.Count, cancellationToken);
        var objectCounts = await db.AdObjectSnapshots.AsNoTracking().Where(item => item.ScanRunId == scanId)
            .GroupBy(item => item.RiskLevel)
            .Select(group => new { Level = group.Key, Count = group.Count() })
            .ToDictionaryAsync(item => item.Level, item => item.Count, cancellationToken);

        var objects = db.AdObjectSnapshots.AsNoTracking().Where(item => item.ScanRunId == scanId);
        var findings = db.RiskFindings.AsNoTracking().Where(item => item.ScanRunId == scanId);
        var serviceCount = await objects.CountAsync(item => item.IsServiceAccount, cancellationToken);
        var privilegedCount = await objects.CountAsync(item => item.IsPrivileged, cancellationToken);
        var staleCount = await findings.Where(item => item.RuleId == RiskRuleIds.StaleEnabledAccount)
            .Select(item => item.ObjectGuid).Distinct().CountAsync(cancellationToken);

        // NOCASE combines category spelling variants without fixing a category list in code.
        var categories = await findings.Where(item => item.Category != "")
            .GroupBy(item => EF.Functions.Collate(item.Category, "NOCASE"))
            .Select(group => new DashboardCategoryViewModel
            {
                Category = group.Min(item => item.Category)!,
                FindingsCount = group.Count(),
                AffectedAccounts = group.Select(item => item.ObjectGuid).Distinct().Count()
            })
            .OrderByDescending(item => item.FindingsCount).ThenBy(item => item.Category)
            .ToListAsync(cancellationToken);

        var historyNewestFirst = await db.ScanRuns.AsNoTracking()
            .Where(run => run.Status == ScanStatus.Completed || run.Status == ScanStatus.CompletedWithErrors)
            .OrderByDescending(run => run.Id)
            .Take(ListLimit)
            .Select(run => new DashboardScoreHistoryViewModel
            {
                ScanRunId = run.Id, StartedAtUtc = run.StartedAtUtc,
                AdSecurityScore = run.AdSecurityScore
            }).ToListAsync(cancellationToken);
        historyNewestFirst.Reverse();

        return new DashboardViewModel
        {
            ScanRunId = scanId,
            ScanStartedAtUtc = latestCompleted.StartedAtUtc,
            ScanFinishedAtUtc = latestCompleted.FinishedAtUtc,
            ScanStatus = latestCompleted.Status,
            Server = latestCompleted.Server,
            BaseDn = latestCompleted.BaseDn,
            AdSecurityScore = latestCompleted.AdSecurityScore,
            TotalObjects = latestCompleted.ObjectsScanned,
            TotalFindings = latestCompleted.FindingsCount,
            CriticalFindings = findingCounts.GetValueOrDefault(RiskSeverity.Critical),
            HighFindings = findingCounts.GetValueOrDefault(RiskSeverity.High),
            MediumFindings = findingCounts.GetValueOrDefault(RiskSeverity.Medium),
            LowFindings = findingCounts.GetValueOrDefault(RiskSeverity.Low),
            CriticalObjects = objectCounts.GetValueOrDefault(RiskSeverity.Critical),
            HighObjects = objectCounts.GetValueOrDefault(RiskSeverity.High),
            MediumObjects = objectCounts.GetValueOrDefault(RiskSeverity.Medium),
            LowObjects = objectCounts.GetValueOrDefault(RiskSeverity.Low),
            ServiceAccounts = serviceCount,
            PrivilegedAccounts = privilegedCount,
            StaleAccounts = staleCount,
            ErrorsCount = latestCompleted.ErrorsCount,
            ScanRunning = scanRunning,
            LatestFailedScan = latestFailed,
            TopRiskyAccounts = await GetAccountsAsync(objects, ListLimit, cancellationToken),
            RiskCategories = categories,
            ScoreHistory = historyNewestFirst,
            HighRiskPrivilegedAccounts = await GetAccountsAsync(
                objects.Where(item => item.IsPrivileged &&
                    (item.RiskLevel == RiskSeverity.High || item.RiskLevel == RiskSeverity.Critical)),
                ListLimit, cancellationToken),
            RiskyServiceAccounts = await GetAccountsAsync(
                objects.Where(item => item.IsServiceAccount), ListLimit, cancellationToken),
            MostImportantFindings = await GetImportantFindingsAsync(scanId, cancellationToken)
        };
    }

    private async Task<IReadOnlyList<DashboardAccountViewModel>> GetAccountsAsync(
        IQueryable<Domain.Entities.AdObjectSnapshot> objects,
        int limit,
        CancellationToken cancellationToken)
    {
        var candidates = await objects.Select(item => new DashboardAccountViewModel
            {
                ObjectGuid = item.ObjectGuid,
                AccountName = item.SamAccountName ?? item.DisplayName ?? item.DistinguishedName,
                RiskScore = item.RiskScore,
                RiskLevel = item.RiskLevel,
                FindingsCount = db.RiskFindings.Count(finding =>
                    finding.ScanRunId == item.ScanRunId && finding.ObjectGuid == item.ObjectGuid),
                CriticalFindingsCount = db.RiskFindings.Count(finding =>
                    finding.ScanRunId == item.ScanRunId && finding.ObjectGuid == item.ObjectGuid
                    && finding.Severity == RiskSeverity.Critical),
                IsPrivileged = item.IsPrivileged,
                IsServiceAccount = item.IsServiceAccount
            })
            .OrderByDescending(item => item.RiskScore)
            .ThenByDescending(item => item.CriticalFindingsCount)
            .ThenByDescending(item => item.FindingsCount)
            .ThenBy(item => item.AccountName)
            .ThenBy(item => item.ObjectGuid)
            .Take(limit)
            .ToListAsync(cancellationToken);
        return candidates;
    }

    private async Task<IReadOnlyList<DashboardFindingViewModel>> GetImportantFindingsAsync(
        long scanId, CancellationToken cancellationToken)
    {
        var important = await (from finding in db.RiskFindings.AsNoTracking()
                               join account in db.AdObjectSnapshots.AsNoTracking()
                                   on new { finding.ScanRunId, finding.ObjectGuid }
                                   equals new { account.ScanRunId, account.ObjectGuid }
                               where finding.ScanRunId == scanId
                               select new DashboardFindingViewModel
                               {
                                   ObjectName = finding.ObjectName,
                                   ObjectGuid = finding.ObjectGuid,
                                   Severity = finding.Severity,
                                   RuleId = finding.RuleId,
                                   Title = finding.Title,
                                   RiskPoints = finding.RiskPoints,
                                   ObjectRiskScore = account.RiskScore
                               })
            .OrderByDescending(item => item.Severity)
            .ThenByDescending(item => item.RiskPoints)
            .ThenByDescending(item => item.ObjectRiskScore)
            .ThenBy(item => item.ObjectName)
            .ThenBy(item => item.ObjectGuid)
            .ThenBy(item => item.RuleId)
            .Take(ListLimit)
            .ToListAsync(cancellationToken);
        return important;
    }
}

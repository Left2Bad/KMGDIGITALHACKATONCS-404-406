using IdentityRiskAnalyzer.Web.Data;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Services.Scanning;
using IdentityRiskAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityRiskAnalyzer.Web.Controllers;

[Route("Scans")]
public sealed class ScansController(AppDbContext db, IActiveDirectoryScanService scans) : Controller
{
    [HttpGet("")]
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        var runs = await db.ScanRuns.AsNoTracking().OrderByDescending(run => run.Id)
            .Take(100).Select(run => new ScanListItemViewModel
            {
                Id = run.Id, StartedAtUtc = run.StartedAtUtc, FinishedAtUtc = run.FinishedAtUtc,
                Status = run.Status, Server = run.Server, ObjectsScanned = run.ObjectsScanned,
                FindingsCount = run.FindingsCount, ErrorsCount = run.ErrorsCount,
                AdSecurityScore = run.AdSecurityScore
            }).ToListAsync(cancellationToken);
        return View(new ScanListViewModel { Scans = runs, Message = TempData["ScanMessage"] as string });
    }

    [HttpPost("Start")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Start(CancellationToken cancellationToken)
    {
        var result = await scans.RunScanAsync(cancellationToken);
        if (result.AlreadyRunning || result.ScanRunId == 0)
        {
            TempData["ScanMessage"] = result.ErrorMessage ?? "The scan did not start.";
            return RedirectToAction(nameof(Index));
        }
        return RedirectToAction(nameof(Details), new { id = result.ScanRunId });
    }

    [HttpGet("{id:long}")]
    public async Task<IActionResult> Details(long id, CancellationToken cancellationToken)
    {
        var run = await db.ScanRuns.AsNoTracking().Where(item => item.Id == id)
            .Select(item => new { item.Id, item.StartedAtUtc, item.FinishedAtUtc, item.Status,
                item.Server, item.BaseDn, item.ObjectsScanned, item.FindingsCount,
                item.ErrorsCount, item.AdSecurityScore, item.ErrorMessage })
            .SingleOrDefaultAsync(cancellationToken);
        if (run is null) return NotFound();

        var findingCounts = await db.RiskFindings.AsNoTracking().Where(item => item.ScanRunId == id)
            .GroupBy(item => item.Severity).Select(group => new { Severity = group.Key, Count = group.Count() })
            .ToDictionaryAsync(item => item.Severity, item => item.Count, cancellationToken);
        var objectCounts = await db.AdObjectSnapshots.AsNoTracking().Where(item => item.ScanRunId == id)
            .GroupBy(item => item.RiskLevel).Select(group => new { Level = group.Key, Count = group.Count() })
            .ToDictionaryAsync(item => item.Level, item => item.Count, cancellationToken);
        var findingsByObject = await db.RiskFindings.AsNoTracking().Where(item => item.ScanRunId == id)
            .GroupBy(item => item.ObjectGuid).Select(group => new { ObjectGuid = group.Key, Count = group.Count() })
            .ToDictionaryAsync(item => item.ObjectGuid, item => item.Count, cancellationToken);
        var topSnapshots = await db.AdObjectSnapshots.AsNoTracking().Where(item => item.ScanRunId == id)
            .OrderByDescending(item => item.RiskScore).ThenBy(item => item.SamAccountName)
            .Take(10).Select(item => new { item.ObjectGuid, item.SamAccountName, item.DisplayName,
                item.DistinguishedName, item.RiskScore, item.RiskLevel })
            .ToListAsync(cancellationToken);
        var top = topSnapshots.Select(item => new TopRiskyAccountViewModel
        {
            ObjectGuid = item.ObjectGuid, Name = item.SamAccountName ?? item.DisplayName ?? item.DistinguishedName,
            RiskScore = item.RiskScore, RiskLevel = item.RiskLevel,
            FindingsCount = findingsByObject.GetValueOrDefault(item.ObjectGuid)
        }).ToArray();
        var findingRows = await db.RiskFindings.AsNoTracking().Where(item => item.ScanRunId == id)
            .OrderByDescending(item => item.Severity).ThenBy(item => item.ObjectName)
            .Take(20).Select(item => new ScanFindingViewModel
            { ObjectName = item.ObjectName, RuleId = item.RuleId, Severity = item.Severity, Title = item.Title })
            .ToListAsync(cancellationToken);

        return View(new ScanDetailsViewModel
        {
            Summary = new ScanListItemViewModel
            {
                Id = run.Id, StartedAtUtc = run.StartedAtUtc, FinishedAtUtc = run.FinishedAtUtc,
                Status = run.Status, Server = run.Server, ObjectsScanned = run.ObjectsScanned,
                FindingsCount = run.FindingsCount, ErrorsCount = run.ErrorsCount,
                AdSecurityScore = run.AdSecurityScore
            },
            BaseDn = run.BaseDn, ErrorMessage = run.ErrorMessage,
            FindingSeverityCounts = findingCounts, ObjectRiskCounts = objectCounts,
            TopRiskyAccounts = top, Findings = findingRows
        });
    }
}

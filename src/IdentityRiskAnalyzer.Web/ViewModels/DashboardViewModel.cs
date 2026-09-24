using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class DashboardViewModel
{
    public bool HasData => ScanRunId.HasValue;
    public long? ScanRunId { get; init; }
    public DateTimeOffset? ScanStartedAtUtc { get; init; }
    public DateTimeOffset? ScanFinishedAtUtc { get; init; }
    public ScanStatus? ScanStatus { get; init; }
    public string? Server { get; init; }
    public string? BaseDn { get; init; }
    public int? AdSecurityScore { get; init; }
    public int TotalObjects { get; init; }
    public int TotalFindings { get; init; }
    public int CriticalFindings { get; init; }
    public int HighFindings { get; init; }
    public int MediumFindings { get; init; }
    public int LowFindings { get; init; }
    public int CriticalObjects { get; init; }
    public int HighObjects { get; init; }
    public int MediumObjects { get; init; }
    public int LowObjects { get; init; }
    public int ServiceAccounts { get; init; }
    public int PrivilegedAccounts { get; init; }
    public int StaleAccounts { get; init; }
    public int ErrorsCount { get; init; }
    public bool ScanRunning { get; init; }
    public DashboardFailedScanViewModel? LatestFailedScan { get; init; }
    public IReadOnlyList<DashboardAccountViewModel> TopRiskyAccounts { get; init; } = [];
    public IReadOnlyList<DashboardCategoryViewModel> RiskCategories { get; init; } = [];
    public IReadOnlyList<DashboardScoreHistoryViewModel> ScoreHistory { get; init; } = [];
    public IReadOnlyList<DashboardAccountViewModel> HighRiskPrivilegedAccounts { get; init; } = [];
    public IReadOnlyList<DashboardAccountViewModel> RiskyServiceAccounts { get; init; } = [];
    public IReadOnlyList<DashboardFindingViewModel> MostImportantFindings { get; init; } = [];
    public TimeSpan? ScanDuration => ScanFinishedAtUtc - ScanStartedAtUtc;
}

public sealed class DashboardFailedScanViewModel
{
    public long ScanRunId { get; init; }
    public DateTimeOffset StartedAtUtc { get; init; }
    public DateTimeOffset? FinishedAtUtc { get; init; }
    public string? ErrorMessage { get; init; }
}

public sealed class DashboardAccountViewModel
{
    public Guid ObjectGuid { get; init; }
    public string AccountName { get; init; } = string.Empty;
    public int RiskScore { get; init; }
    public RiskSeverity RiskLevel { get; init; }
    public int FindingsCount { get; init; }
    public int CriticalFindingsCount { get; init; }
    public bool IsPrivileged { get; init; }
    public bool IsServiceAccount { get; init; }
}

public sealed class DashboardCategoryViewModel
{
    public string Category { get; init; } = string.Empty;
    public int FindingsCount { get; init; }
    public int AffectedAccounts { get; init; }
}

public sealed class DashboardScoreHistoryViewModel
{
    public long ScanRunId { get; init; }
    public DateTimeOffset StartedAtUtc { get; init; }
    public int? AdSecurityScore { get; init; }
}

public sealed class DashboardFindingViewModel
{
    public string ObjectName { get; init; } = string.Empty;
    public Guid ObjectGuid { get; init; }
    public RiskSeverity Severity { get; init; }
    public string RuleId { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public int RiskPoints { get; init; }
    public int ObjectRiskScore { get; init; }
}

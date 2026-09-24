using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class ScanDetailsViewModel
{
    public required ScanListItemViewModel Summary { get; init; }
    public string BaseDn { get; init; } = string.Empty;
    public string? ErrorMessage { get; init; }
    public IReadOnlyDictionary<RiskSeverity, int> FindingSeverityCounts { get; init; } = new Dictionary<RiskSeverity, int>();
    public IReadOnlyDictionary<RiskSeverity, int> ObjectRiskCounts { get; init; } = new Dictionary<RiskSeverity, int>();
    public IReadOnlyList<TopRiskyAccountViewModel> TopRiskyAccounts { get; init; } = [];
    public IReadOnlyList<ScanFindingViewModel> Findings { get; init; } = [];
}

public sealed class TopRiskyAccountViewModel
{
    public Guid ObjectGuid { get; init; }
    public string Name { get; init; } = string.Empty;
    public int RiskScore { get; init; }
    public RiskSeverity RiskLevel { get; init; }
    public int FindingsCount { get; init; }
}

public sealed class ScanFindingViewModel
{
    public string ObjectName { get; init; } = string.Empty;
    public string RuleId { get; init; } = string.Empty;
    public RiskSeverity Severity { get; init; }
    public string Title { get; init; } = string.Empty;
}

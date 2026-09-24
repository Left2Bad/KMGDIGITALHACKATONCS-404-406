using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class ObjectRiskScoreResult
{
    public Guid ObjectGuid { get; init; }
    public string ObjectName { get; init; } = string.Empty;
    public int RawScore { get; init; }
    public int RiskScore { get; init; }
    public RiskSeverity RiskLevel { get; init; }
    public int FindingsCount { get; init; }
    public int CriticalFindings { get; init; }
    public int HighFindings { get; init; }
    public int MediumFindings { get; init; }
    public int LowFindings { get; init; }
    public IReadOnlyList<RiskFindingResult> Findings { get; init; } = Array.Empty<RiskFindingResult>();
}

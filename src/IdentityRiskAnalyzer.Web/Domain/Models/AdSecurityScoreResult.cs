using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class AdSecurityScoreResult
{
    public int? SecurityScore { get; init; }
    public int AnalysedObjects { get; init; }
    public int TotalObjects => AnalysedObjects;
    public double? AverageRiskScore { get; init; }
    public int CriticalObjects { get; init; }
    public int HighRiskObjects { get; init; }
    public int MediumRiskObjects { get; init; }
    public int LowRiskObjects { get; init; }
    public int TotalFindings { get; init; }
    public int CriticalFindings { get; init; }
    public int HighFindings { get; init; }
    public int MediumFindings { get; init; }
    public int LowFindings { get; init; }
    public IReadOnlyList<RiskCategorySummary> CategorySummaries { get; init; } = Array.Empty<RiskCategorySummary>();
    public IReadOnlyList<ObjectRiskScoreResult> TopRiskyObjects { get; init; } = Array.Empty<ObjectRiskScoreResult>();
}

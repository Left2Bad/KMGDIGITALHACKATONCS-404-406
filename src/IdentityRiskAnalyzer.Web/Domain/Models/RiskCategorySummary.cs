namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class RiskCategorySummary
{
    public string Category { get; init; } = string.Empty;
    public int FindingsCount { get; init; }
    public int AffectedObjects { get; init; }
}

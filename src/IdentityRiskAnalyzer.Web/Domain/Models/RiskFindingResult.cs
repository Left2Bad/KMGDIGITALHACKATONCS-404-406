using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class RiskFindingResult
{
    public Guid ObjectGuid { get; init; }
    public AdObjectType ObjectType { get; init; }
    public string ObjectName { get; init; } = string.Empty;
    public string RuleId { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string? Evidence { get; init; }
    public string Recommendation { get; init; } = string.Empty;
    public int RiskPoints { get; init; }
    public RiskSeverity Severity { get; init; }
}

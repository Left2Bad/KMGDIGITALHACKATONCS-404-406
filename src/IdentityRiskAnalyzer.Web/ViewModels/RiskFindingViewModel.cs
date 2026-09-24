using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class RiskFindingViewModel
{
    public string RuleId { get; init; } = string.Empty;
    public RiskSeverity Severity { get; init; }
    public string Title { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string Evidence { get; init; } = string.Empty;
    public string Recommendation { get; init; } = string.Empty;
    public int RiskPoints { get; init; }

    public string SeverityCssClass => Severity switch
    {
        RiskSeverity.Critical => "text-bg-danger",
        RiskSeverity.High => "text-bg-warning",
        RiskSeverity.Medium => "text-bg-info",
        _ => "text-bg-secondary"
    };

    public static RiskFindingViewModel From(RiskFindingResult finding) => new()
    {
        RuleId = finding.RuleId,
        Severity = finding.Severity,
        Title = finding.Title,
        Description = finding.Description,
        Evidence = finding.Evidence ?? string.Empty,
        Recommendation = finding.Recommendation,
        RiskPoints = finding.RiskPoints
    };
}

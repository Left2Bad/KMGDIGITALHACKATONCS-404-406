using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class ObjectRiskScoreViewModel
{
    public int Score { get; init; }
    public int RawScore { get; init; }
    public RiskSeverity RiskLevel { get; init; } = RiskSeverity.Low;
    public int FindingsCount { get; init; }

    public string RiskLevelCssClass => RiskLevel switch
    {
        RiskSeverity.Critical => "text-bg-danger",
        RiskSeverity.High => "text-bg-warning",
        RiskSeverity.Medium => "text-bg-info",
        _ => "text-bg-success"
    };

    public static ObjectRiskScoreViewModel From(ObjectRiskScoreResult result) => new()
    {
        Score = result.RiskScore,
        RawScore = result.RawScore,
        RiskLevel = result.RiskLevel,
        FindingsCount = result.FindingsCount
    };
}

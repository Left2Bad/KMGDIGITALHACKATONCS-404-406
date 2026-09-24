namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class RiskScoringObject
{
    public Guid ObjectGuid { get; init; }
    public string ObjectName { get; init; } = string.Empty;
}

using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Options;

public sealed class RiskRuleSettings
{
    public int RiskPoints { get; set; }
    public RiskSeverity Severity { get; set; }
}

using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules;

public interface IAdRiskRule
{
    string RuleId { get; }
    string Category { get; }
    IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context);
}

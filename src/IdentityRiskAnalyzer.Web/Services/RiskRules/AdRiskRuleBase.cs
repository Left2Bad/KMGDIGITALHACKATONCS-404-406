using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules;

public abstract class AdRiskRuleBase : IAdRiskRule
{
    public abstract string RuleId { get; }
    public abstract string Category { get; }
    protected abstract string Title { get; }
    protected abstract string Description { get; }
    protected abstract string Recommendation { get; }

    public abstract IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context);

    protected RiskFindingResult Finding(AdRiskEvaluationContext context, string evidence)
    {
        var settings = context.Settings.GetRule(RuleId);
        return new RiskFindingResult
        {
            ObjectGuid = context.User.ObjectGuid,
            ObjectType = context.ObjectType,
            ObjectName = context.ObjectName,
            RuleId = RuleId,
            Category = Category,
            Title = Title,
            Description = Description,
            Evidence = evidence,
            Recommendation = Recommendation,
            RiskPoints = settings.RiskPoints,
            Severity = settings.Severity
        };
    }
}

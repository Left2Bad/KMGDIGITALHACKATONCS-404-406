using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Privilege;

public sealed class DirectPrivilegedMembershipRule : AdRiskRuleBase
{
    public override string RuleId => RiskRuleIds.DirectPrivilegedMembership;
    public override string Category => RiskCategories.Privilege;
    protected override string Title => "Direct membership in a privileged group";
    protected override string Description => "The account is directly assigned to a configured privileged group.";
    protected override string Recommendation => "Проверить необходимость прямого членства в административной группе и оставить его только при подтвержденной рабочей необходимости.";

    public override IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context)
    {
        foreach (var membership in PrivilegedMembershipRuleHelpers.GetDistinctMemberships(context).Where(item => item.IsDirect))
        {
            yield return Finding(context, $"Target privileged group: {membership.GroupName}{Environment.NewLine}Membership: Direct; depth: {membership.Depth}.{Environment.NewLine}Path: {PrivilegedMembershipRuleHelpers.FormatPath(context, membership)}");
        }
    }
}

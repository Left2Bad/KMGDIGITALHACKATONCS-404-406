using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Privilege;

public sealed class MultipleAdministrativeRolesRule : AdRiskRuleBase
{
    public override string RuleId => RiskRuleIds.MultipleAdministrativeRoles;
    public override string Category => RiskCategories.Privilege;
    protected override string Title => "Membership in multiple privileged groups";
    protected override string Description => "The account has distinct membership paths to two or more configured privileged groups.";
    protected override string Recommendation => "Проверить совокупность административных ролей и подтвердить необходимость каждой из них с владельцами систем.";

    public override IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context)
    {
        var memberships = PrivilegedMembershipRuleHelpers.GetDistinctMemberships(context);
        if (memberships.Count < 2)
        {
            yield break;
        }

        var names = memberships.Select(membership => membership.GroupName).ToArray();
        yield return Finding(context, $"Account has memberships in {memberships.Count} distinct privileged groups:{Environment.NewLine}{string.Join(Environment.NewLine, names)}");
    }
}

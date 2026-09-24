using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Privilege;

public sealed class NestedPrivilegedMembershipRule : AdRiskRuleBase
{
    public override string RuleId => RiskRuleIds.NestedPrivilegedMembership;
    public override string Category => RiskCategories.Privilege;
    protected override string Title => "Nested membership in a privileged group";
    protected override string Description => "The account reaches a configured privileged group through nested group membership.";
    protected override string Recommendation => "Проверить необходимость всей цепочки вложенного членства. Убедиться, что административные полномочия пользователя действительно требуются, и удалить избыточное назначение после согласования с ответственными лицами.";

    public override IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context)
    {
        foreach (var membership in PrivilegedMembershipRuleHelpers.GetDistinctMemberships(context).Where(item => !item.IsDirect))
        {
            yield return Finding(context, $"Target privileged group: {membership.GroupName}{Environment.NewLine}Membership: Nested; depth: {membership.Depth}.{Environment.NewLine}Full path: {PrivilegedMembershipRuleHelpers.FormatPath(context, membership)}");
        }
    }
}

using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Delegation;

public sealed class ConstrainedDelegationRule : DelegationRuleBase
{
    public override string RuleId => RiskRuleIds.ConstrainedDelegation;
    protected override string Title => "Constrained Kerberos delegation is configured";
    protected override string Description => "The account has configured constrained-delegation service targets that require review.";
    protected override string Recommendation => "Проверить каждый target service и подтвердить, что делегирование ограничено необходимыми сервисами и владельцами.";
    protected override DelegationType TargetType => DelegationType.Constrained;
}

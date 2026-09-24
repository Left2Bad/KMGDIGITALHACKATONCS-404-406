using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Delegation;

public sealed class UnconstrainedDelegationRule : DelegationRuleBase
{
    public override string RuleId => RiskRuleIds.UnconstrainedDelegation;
    protected override string Title => "Unconstrained Kerberos delegation is configured";
    protected override string Description => "The account is configured for unconstrained Kerberos delegation and requires review.";
    protected override string Recommendation => "Проверить необходимость unconstrained delegation и рассмотреть более ограниченную конфигурацию после оценки зависимостей.";
    protected override DelegationType TargetType => DelegationType.Unconstrained;
}

using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Delegation;

public sealed class ResourceBasedConstrainedDelegationRule : DelegationRuleBase
{
    public override string RuleId => RiskRuleIds.ResourceBasedConstrainedDelegation;
    protected override string Title => "Resource-Based Constrained Delegation is configured";
    protected override string Description => "Resource-Based Constrained Delegation is configured; the security descriptor ACL has not been evaluated in this MVP.";
    protected override string Recommendation => "Провести отдельную проверку ACL Resource-Based Constrained Delegation и убедиться, что делегирование выдано только необходимым субъектам.";
    protected override DelegationType TargetType => DelegationType.ResourceBasedConstrained;
}

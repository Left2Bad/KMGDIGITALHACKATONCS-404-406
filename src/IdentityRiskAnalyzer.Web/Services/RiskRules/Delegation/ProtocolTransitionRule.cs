using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Delegation;

public sealed class ProtocolTransitionRule : DelegationRuleBase
{
    public override string RuleId => RiskRuleIds.ProtocolTransition;
    protected override string Title => "Kerberos protocol transition is configured";
    protected override string Description => "Protocol Transition is enabled with constrained-delegation targets and requires review.";
    protected override string Recommendation => "Проверить необходимость Protocol Transition и согласованность каждого разрешенного target service.";
    protected override DelegationType TargetType => DelegationType.ProtocolTransition;
}

using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Account;

public sealed class LockedAccountRule : AdRiskRuleBase
{
    public override string RuleId => RiskRuleIds.LockedAccount;
    public override string Category => RiskCategories.Account;
    protected override string Title => "Account is currently locked";
    protected override string Description => "The computed Active Directory account-control flags indicate a current lockout.";
    protected override string Recommendation => "Проверить причину блокировки и применить установленную процедуру разблокировки после подтверждения владельца учетной записи.";

    public override IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context)
    {
        if (UserAccountControlHelper.IsLocked(context.User.ComputedUserAccountControl))
        {
            yield return Finding(context, "msDS-User-Account-Control-Computed contains the LOCKOUT flag.");
        }
    }
}

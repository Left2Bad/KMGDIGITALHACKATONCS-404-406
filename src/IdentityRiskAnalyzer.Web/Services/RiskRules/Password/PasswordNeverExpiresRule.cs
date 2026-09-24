using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Password;

public sealed class PasswordNeverExpiresRule : AdRiskRuleBase
{
    public override string RuleId => RiskRuleIds.PasswordNeverExpires;
    public override string Category => RiskCategories.Password;
    protected override string Title => "Password is configured to never expire";
    protected override string Description => "The account has the DONT_EXPIRE_PASSWORD user-account-control flag.";
    protected override string Recommendation => "Проверить исключение из политики смены пароля и применить утвержденные требования к учетным данным.";

    public override IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context)
    {
        if (UserAccountControlHelper.HasFlag(context.User.UserAccountControl, UserAccountControlFlags.DontExpirePassword))
        {
            yield return Finding(context, "userAccountControl contains DONT_EXPIRE_PASSWORD.");
        }
    }
}

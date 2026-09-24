using System.Globalization;
using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Account;

public sealed class ExpiredAccountRule : AdRiskRuleBase
{
    public override string RuleId => RiskRuleIds.ExpiredAccount;
    public override string Category => RiskCategories.Account;
    protected override string Title => "Account expiration date has passed";
    protected override string Description => "The account has an expiration date earlier than the current evaluation time.";
    protected override string Recommendation => "Проверить необходимость сохранения истекшей учетной записи и корректность установленного срока действия.";

    public override IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context)
    {
        var expiration = context.User.AccountExpiresUtc;
        if (!expiration.HasValue || expiration.Value >= context.CurrentUtc)
        {
            yield break;
        }

        yield return Finding(context, $"Account expiration date: {expiration.Value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture)}; current time: {context.CurrentUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture)}.");
    }
}

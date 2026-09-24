using System.Globalization;
using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Password;

public sealed class OldPasswordRule : AdRiskRuleBase
{
    public override string RuleId => RiskRuleIds.OldPassword;
    public override string Category => RiskCategories.Password;
    protected override string Title => "Password has not been changed recently";
    protected override string Description => "The normalized password-last-set timestamp is at or beyond the configured password-age threshold.";
    protected override string Recommendation => "Проверить дату последней смены пароля и применить действующую политику паролей с учетом типа учетной записи.";

    public override IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context)
    {
        var passwordLastSet = context.User.PasswordLastSetUtc;
        if (!passwordLastSet.HasValue)
        {
            yield break;
        }

        var ageDays = (context.CurrentUtc - passwordLastSet.Value).TotalDays;
        if (ageDays < context.Settings.OldPasswordDays)
        {
            yield break;
        }

        yield return Finding(context, $"Password last changed: {passwordLastSet.Value.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}; password age: {Math.Floor(ageDays)} days; configured threshold: {context.Settings.OldPasswordDays} days.");
    }
}

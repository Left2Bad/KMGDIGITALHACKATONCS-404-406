using System.Globalization;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Account;

public sealed class StaleEnabledAccountRule : AdRiskRuleBase
{
    public override string RuleId => RiskRuleIds.StaleEnabledAccount;
    public override string Category => RiskCategories.Account;
    protected override string Title => "Enabled account has been inactive";
    protected override string Description => "The enabled account has no replicated activity within the configured inactivity period.";
    protected override string Recommendation => "Проверить у владельца учетной записи, используется ли она. Если учетная запись больше не требуется, рассмотреть ее отключение в соответствии с внутренними процедурами.";

    public override IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context)
    {
        var lastActivity = context.User.LastKnownActivityUtc;
        if (UserAccountControlHelper.IsDisabled(context.User.UserAccountControl)
            || !lastActivity.HasValue)
        {
            yield break;
        }

        var inactiveDays = (context.CurrentUtc - lastActivity.Value).TotalDays;
        if (inactiveDays < context.Settings.InactiveUserDays)
        {
            yield break;
        }

        var evidence = $"Last known activity: {lastActivity.Value.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}; current date: {context.CurrentUtc.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}; inactive period: {Math.Floor(inactiveDays)} days; configured threshold: {context.Settings.InactiveUserDays} days.";
        yield return Finding(context, evidence);
    }
}

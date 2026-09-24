using System.Globalization;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Privilege;

public sealed class InactivePrivilegedAccountRule : AdRiskRuleBase
{
    public override string RuleId => RiskRuleIds.InactivePrivilegedAccount;
    public override string Category => RiskCategories.Privilege;
    protected override string Title => "Privileged account has been inactive";
    protected override string Description => "The enabled privileged account has no replicated activity within the stricter privileged-account inactivity period.";
    protected override string Recommendation => "Подтвердить необходимость привилегированной учетной записи и проверить ее у владельца; если она больше не требуется, рассмотреть отключение по внутренней процедуре.";

    public override IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context)
    {
        var lastActivity = context.User.LastKnownActivityUtc;
        if (PrivilegedMembershipRuleHelpers.GetDistinctMemberships(context).Count == 0
            || UserAccountControlHelper.IsDisabled(context.User.UserAccountControl)
            || !lastActivity.HasValue)
        {
            yield break;
        }

        var inactiveDays = (context.CurrentUtc - lastActivity.Value).TotalDays;
        if (inactiveDays < context.Settings.InactivePrivilegedUserDays)
        {
            yield break;
        }

        yield return Finding(context, $"Last known activity: {lastActivity.Value.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}; inactive period: {Math.Floor(inactiveDays)} days; configured privileged-account threshold: {context.Settings.InactivePrivilegedUserDays} days.");
    }
}

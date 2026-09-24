using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Spn;

public sealed class DuplicateSpnRule : AdRiskRuleBase
{
    public override string RuleId => RiskRuleIds.DuplicateSpn;
    public override string Category => RiskCategories.Spn;
    protected override string Title => "Service Principal Name is assigned to multiple objects";
    protected override string Description => "The same Service Principal Name is present on multiple distinct directory objects.";
    protected override string Recommendation => "Проверить владельцев объектов и потребителей SPN, затем устранить дублирование в соответствии с процедурой управления Active Directory.";

    public override IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context)
    {
        foreach (var duplicate in (context.DuplicateSpns ?? Array.Empty<DuplicateSpnEvidence>())
            .Where(item => item.ObjectGuid == context.User.ObjectGuid && !string.IsNullOrWhiteSpace(item.ServicePrincipalName))
            .GroupBy(item => item.ServicePrincipalName.Trim(), StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(item => item.ServicePrincipalName, StringComparer.OrdinalIgnoreCase))
        {
            var evidence = $"Duplicate SPN: {duplicate.ServicePrincipalName.Trim()}{Environment.NewLine}Also assigned to: {string.Join(", ", duplicate.OtherObjectNames.Where(name => !string.IsNullOrWhiteSpace(name)).Distinct(StringComparer.OrdinalIgnoreCase))}";
            yield return Finding(context, evidence);
        }
    }
}

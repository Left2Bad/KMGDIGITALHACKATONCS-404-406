using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.ActiveDirectory;

public sealed class SidHistoryRule : AdRiskRuleBase
{
    private const int MaximumValuesInEvidence = 10;

    public override string RuleId => RiskRuleIds.SidHistoryPresent;
    public override string Category => RiskCategories.ActiveDirectory;
    protected override string Title => "SIDHistory values are present";
    protected override string Description => "The account has SIDHistory values that require validation; their presence alone does not establish misuse.";
    protected override string Recommendation => "Проверить происхождение SIDHistory и необходимость его сохранения. Убедиться, что значения соответствуют легитимной миграции и не дают неожиданных полномочий.";

    public override IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context)
    {
        var values = (context.User.SidHistory ?? Array.Empty<string>())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToArray();
        if (values.Length == 0)
        {
            yield break;
        }

        var shown = values.Take(MaximumValuesInEvidence).ToArray();
        var evidence = $"SIDHistory count: {values.Length}; values shown: {shown.Length}.{Environment.NewLine}{string.Join(Environment.NewLine, shown)}";
        if (values.Length > shown.Length)
        {
            evidence += $"{Environment.NewLine}Additional values omitted: {values.Length - shown.Length}.";
        }

        yield return Finding(context, evidence);
    }
}

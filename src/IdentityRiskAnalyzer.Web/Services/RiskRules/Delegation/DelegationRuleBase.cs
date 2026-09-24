using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules.Delegation;

public abstract class DelegationRuleBase : AdRiskRuleBase
{
    protected abstract DelegationType TargetType { get; }

    public override string Category => RiskCategories.Delegation;

    public override IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context)
    {
        foreach (var delegation in (context.DelegationResults ?? Array.Empty<DelegationAnalysisResult>())
            .Where(result => result.ObjectGuid == context.User.ObjectGuid && result.DelegationType == TargetType)
            .OrderBy(result => string.Join("|", result.Targets), StringComparer.OrdinalIgnoreCase)
            .ThenBy(result => result.Evidence, StringComparer.Ordinal))
        {
            var evidence = string.IsNullOrWhiteSpace(delegation.Evidence)
                ? $"Detected delegation configuration: {TargetType}."
                : delegation.Evidence;
            if (delegation.Targets.Count > 0
                && !delegation.Targets.Any(target => evidence.Contains(target, StringComparison.OrdinalIgnoreCase)))
            {
                evidence += $"{Environment.NewLine}Targets: {string.Join(", ", delegation.Targets)}";
            }

            yield return Finding(context, evidence);
        }
    }
}

using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.RiskRules;

public sealed class RiskEngine
{
    private readonly IReadOnlyList<IAdRiskRule> _rules;
    private readonly ILogger<RiskEngine> _logger;

    public RiskEngine(IEnumerable<IAdRiskRule> rules, ILogger<RiskEngine> logger)
    {
        ArgumentNullException.ThrowIfNull(rules);
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _rules = rules.OrderBy(rule => rule.RuleId, StringComparer.Ordinal).ToArray();

        var duplicateRuleId = _rules
            .GroupBy(rule => rule.RuleId, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicateRuleId is not null)
        {
            throw new ArgumentException($"More than one risk rule uses RuleId '{duplicateRuleId.Key}'.", nameof(rules));
        }
    }

    public IReadOnlyList<RiskFindingResult> Evaluate(AdRiskEvaluationContext context)
        => EvaluateWithDiagnostics(context).Findings;

    public RiskEvaluationResult EvaluateWithDiagnostics(AdRiskEvaluationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        _logger.LogInformation("Risk evaluation started for object {ObjectGuid}.", context.User.ObjectGuid);
        var (findings, ruleErrors) = EvaluateCore(context);
        var distinct = Deduplicate(findings);
        _logger.LogInformation(
            "Risk evaluation completed for 1 object: {RulesExecuted} rules, {FindingsProduced} findings, {RuleErrors} rule errors.",
            _rules.Count,
            distinct.Count,
            ruleErrors);
        return new RiskEvaluationResult(distinct, ruleErrors);
    }

    public IReadOnlyList<RiskFindingResult> EvaluateAll(IEnumerable<AdRiskEvaluationContext> contexts)
    {
        ArgumentNullException.ThrowIfNull(contexts);
        var contextList = contexts.ToArray();
        _logger.LogInformation("Batch risk evaluation started for {ObjectCount} objects using {RuleCount} rules.", contextList.Length, _rules.Count);

        var findings = new List<RiskFindingResult>();
        var ruleErrors = 0;
        foreach (var context in contextList)
        {
            var (objectFindings, objectErrors) = EvaluateCore(context);
            findings.AddRange(objectFindings);
            ruleErrors += objectErrors;
        }

        var distinct = Deduplicate(findings);
        _logger.LogInformation(
            "Batch risk evaluation completed: {ObjectCount} objects analysed, {RuleCount} rules executed per object, {FindingCount} findings produced, {RuleErrors} rule errors.",
            contextList.Length,
            _rules.Count,
            distinct.Count,
            ruleErrors);
        return distinct;
    }

    private (IReadOnlyList<RiskFindingResult> Findings, int RuleErrors) EvaluateCore(AdRiskEvaluationContext context)
    {
        var findings = new List<RiskFindingResult>();
        var ruleErrors = 0;
        foreach (var rule in _rules)
        {
            try
            {
                var results = rule.Evaluate(context);
                if (results is not null)
                {
                    findings.AddRange(results.Where(finding => finding is not null));
                }
            }
            catch (Exception exception)
            {
                ruleErrors++;
                _logger.LogError(exception, "Risk rule {RuleId} failed for object {ObjectGuid}; remaining rules will continue.", rule.RuleId, context.User.ObjectGuid);
            }
        }

        return (findings, ruleErrors);
    }

    private static IReadOnlyList<RiskFindingResult> Deduplicate(IEnumerable<RiskFindingResult> findings) => findings
        .GroupBy(finding => (finding.ObjectGuid, finding.RuleId, finding.Evidence), FindingIdentityComparer.Instance)
        .Select(group => group.First())
        .OrderBy(finding => finding.RuleId, StringComparer.Ordinal)
        .ThenBy(finding => finding.ObjectName, StringComparer.OrdinalIgnoreCase)
        .ThenBy(finding => finding.Evidence, StringComparer.Ordinal)
        .ToArray();

    private sealed class FindingIdentityComparer : IEqualityComparer<(Guid ObjectGuid, string RuleId, string? Evidence)>
    {
        public static FindingIdentityComparer Instance { get; } = new();

        public bool Equals((Guid ObjectGuid, string RuleId, string? Evidence) x, (Guid ObjectGuid, string RuleId, string? Evidence) y) =>
            x.ObjectGuid == y.ObjectGuid
            && string.Equals(x.RuleId, y.RuleId, StringComparison.OrdinalIgnoreCase)
            && string.Equals(x.Evidence, y.Evidence, StringComparison.Ordinal);

        public int GetHashCode((Guid ObjectGuid, string RuleId, string? Evidence) value) =>
            HashCode.Combine(
                value.ObjectGuid,
                StringComparer.OrdinalIgnoreCase.GetHashCode(value.RuleId),
                value.Evidence is null ? 0 : StringComparer.Ordinal.GetHashCode(value.Evidence));
    }
}

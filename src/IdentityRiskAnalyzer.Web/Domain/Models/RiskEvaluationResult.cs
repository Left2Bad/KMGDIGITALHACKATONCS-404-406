namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed record RiskEvaluationResult(
    IReadOnlyList<RiskFindingResult> Findings,
    int ErrorsCount);

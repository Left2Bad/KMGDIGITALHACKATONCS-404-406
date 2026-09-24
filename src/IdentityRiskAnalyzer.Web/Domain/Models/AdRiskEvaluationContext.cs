using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Options;

namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class AdRiskEvaluationContext
{
    public required AdUserRecord User { get; init; }
    public required PrivilegeAnalysisResult PrivilegeAnalysis { get; init; }
    public required ServiceAccountClassification ServiceAccountClassification { get; init; }
    public IReadOnlyList<DelegationAnalysisResult> DelegationResults { get; init; } = Array.Empty<DelegationAnalysisResult>();
    public IReadOnlyList<DuplicateSpnEvidence> DuplicateSpns { get; init; } = Array.Empty<DuplicateSpnEvidence>();
    public DateTimeOffset CurrentUtc { get; init; }
    public required RiskSettings Settings { get; init; }
    public AdObjectType ObjectType { get; init; } = AdObjectType.User;

    public string ObjectName => FirstNonEmpty(
        User.SamAccountName,
        User.UserPrincipalName,
        User.DisplayName,
        ServiceAccountClassification.AccountName,
        User.DistinguishedName);

    private static string FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
}

using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class DelegationAnalysisResult
{
    public Guid ObjectGuid { get; init; }
    public string ObjectName { get; init; } = string.Empty;
    public string DistinguishedName { get; init; } = string.Empty;
    public DelegationType DelegationType { get; init; }
    public IReadOnlyList<string> Targets { get; init; } = Array.Empty<string>();
    public string Evidence { get; init; } = string.Empty;
    public bool RequiresDetailedReview { get; init; }
}

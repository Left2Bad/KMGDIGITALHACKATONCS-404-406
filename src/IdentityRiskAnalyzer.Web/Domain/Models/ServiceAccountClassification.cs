using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class ServiceAccountClassification
{
    public Guid ObjectGuid { get; init; }
    public string AccountName { get; init; } = string.Empty;
    public bool IsServiceAccount { get; init; }
    public ServiceAccountDetectionMethod DetectionMethod { get; init; }
    public ServiceAccountDetectionConfidence Confidence { get; init; }
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> ServicePrincipalNames { get; init; } = Array.Empty<string>();
}

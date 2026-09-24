namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class DuplicateSpnEvidence
{
    public Guid ObjectGuid { get; init; }
    public string ObjectName { get; init; } = string.Empty;
    public string ServicePrincipalName { get; init; } = string.Empty;
    public IReadOnlyList<string> OtherObjectNames { get; init; } = Array.Empty<string>();
}

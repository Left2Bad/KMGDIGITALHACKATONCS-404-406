namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class AdGroupRecord
{
    public required Guid ObjectGuid { get; init; }
    public string? Sid { get; init; }
    public required string DistinguishedName { get; init; }
    public string? CommonName { get; init; }
    public string? SamAccountName { get; init; }
    public long GroupType { get; init; }
    public IReadOnlyList<string> MemberDistinguishedNames { get; init; } = Array.Empty<string>();
    public string? Description { get; init; }
    public string? ManagedBy { get; init; }
    public bool MembersComplete { get; init; } = true;
}

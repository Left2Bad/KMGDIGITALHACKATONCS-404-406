namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class PrivilegeAnalysisResult
{
    public Guid UserObjectGuid { get; init; }
    public string UserName { get; init; } = string.Empty;
    public IReadOnlyList<PrivilegedMembershipResult> PrivilegedMemberships { get; init; } = Array.Empty<PrivilegedMembershipResult>();

    public bool IsPrivileged => PrivilegedMemberships.Count > 0;
    public int PrivilegedGroupCount => PrivilegedMemberships.Count;
}

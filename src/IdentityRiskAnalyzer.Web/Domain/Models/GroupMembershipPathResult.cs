namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class GroupMembershipPathResult
{
    public Guid PrincipalObjectGuid { get; init; }
    public string PrincipalName { get; init; } = string.Empty;
    public Guid TargetGroupObjectGuid { get; init; }
    public string TargetGroupName { get; init; } = string.Empty;
    public string TargetGroupDistinguishedName { get; init; } = string.Empty;
    public bool IsDirect { get; init; }
    public int Depth { get; init; }
    public IReadOnlyList<string> PathDistinguishedNames { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> PathDisplayNames { get; init; } = Array.Empty<string>();
}

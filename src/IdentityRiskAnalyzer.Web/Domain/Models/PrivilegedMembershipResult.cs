using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class PrivilegedMembershipResult
{
    public Guid GroupObjectGuid { get; init; }
    public string GroupName { get; init; } = string.Empty;
    public string GroupDistinguishedName { get; init; } = string.Empty;
    public string? GroupSid { get; init; }
    public bool IsDirect { get; init; }
    public int Depth { get; init; }
    public IReadOnlyList<string> PathDisplayNames { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> PathDistinguishedNames { get; init; } = Array.Empty<string>();
    public PrivilegedGroupMatchMethod MatchMethod { get; init; }
    public string? Category { get; init; }
}

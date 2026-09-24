using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class PrivilegedMembershipItemViewModel
{
    public string GroupName { get; init; } = string.Empty;
    public string? GroupSid { get; init; }
    public bool IsDirect { get; init; }
    public int Depth { get; init; }
    public string MatchMethod { get; init; } = string.Empty;
    public string Path { get; init; } = string.Empty;

    public static PrivilegedMembershipItemViewModel From(PrivilegedMembershipResult result) => new()
    {
        GroupName = result.GroupName,
        GroupSid = result.GroupSid,
        IsDirect = result.IsDirect,
        Depth = result.Depth,
        MatchMethod = result.MatchMethod.ToString(),
        Path = string.Join(" → ", result.PathDisplayNames)
    };
}

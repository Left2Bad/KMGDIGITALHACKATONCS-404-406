using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class GroupMembershipPathItemViewModel
{
    public string TargetGroupName { get; init; } = string.Empty;
    public bool IsDirect { get; init; }
    public int Depth { get; init; }
    public string Path { get; init; } = string.Empty;

    public static GroupMembershipPathItemViewModel From(GroupMembershipPathResult result) => new()
    {
        TargetGroupName = result.TargetGroupName,
        IsDirect = result.IsDirect,
        Depth = result.Depth,
        Path = string.Join(" → ", result.PathDisplayNames)
    };
}

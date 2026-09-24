using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class AdGroupListItemViewModel
{
    public Guid ObjectGuid { get; init; }
    public string Name { get; init; } = string.Empty;
    public string? SamAccountName { get; init; }
    public string? Sid { get; init; }
    public string GroupTypeDisplay { get; init; } = string.Empty;
    public int MembersCount { get; init; }
    public string? ManagedBy { get; init; }
    public string DistinguishedName { get; init; } = string.Empty;
    public bool MembersComplete { get; init; }

    public static AdGroupListItemViewModel From(AdGroupRecord group) => new()
    {
        ObjectGuid = group.ObjectGuid,
        Name = group.CommonName ?? group.SamAccountName ?? group.DistinguishedName,
        SamAccountName = group.SamAccountName,
        Sid = group.Sid,
        GroupTypeDisplay = ActiveDirectoryGroupTypeHelper.Describe(group.GroupType),
        MembersCount = group.MemberDistinguishedNames.Count,
        ManagedBy = group.ManagedBy,
        DistinguishedName = group.DistinguishedName,
        MembersComplete = group.MembersComplete
    };
}

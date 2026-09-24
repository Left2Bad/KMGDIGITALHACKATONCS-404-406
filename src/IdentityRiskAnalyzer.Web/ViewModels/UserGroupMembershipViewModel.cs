namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class UserGroupMembershipViewModel
{
    public string UserName { get; init; } = string.Empty;
    public string DistinguishedName { get; init; } = string.Empty;
    public bool IsPrivileged { get; init; }
    public IReadOnlyList<GroupMembershipPathItemViewModel> Memberships { get; init; } = Array.Empty<GroupMembershipPathItemViewModel>();
    public IReadOnlyList<PrivilegedMembershipItemViewModel> PrivilegedMemberships { get; init; } = Array.Empty<PrivilegedMembershipItemViewModel>();
    public IReadOnlyList<DelegationViewModel> Delegations { get; init; } = Array.Empty<DelegationViewModel>();
    public IReadOnlyList<RiskFindingViewModel> RiskFindings { get; init; } = Array.Empty<RiskFindingViewModel>();
    public ObjectRiskScoreViewModel RiskScore { get; init; } = new();
    public ServiceAccountClassificationViewModel ServiceAccountClassification { get; init; } = new();
    public string? ErrorMessage { get; init; }
}

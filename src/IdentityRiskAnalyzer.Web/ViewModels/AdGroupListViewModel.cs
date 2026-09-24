namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class AdGroupListViewModel
{
    public IReadOnlyList<AdGroupListItemViewModel> Groups { get; init; } = Array.Empty<AdGroupListItemViewModel>();
    public int TotalCount { get; init; }
    public int DisplayLimit { get; init; }
    public int IncompleteMemberLists { get; init; }
    public string? ErrorMessage { get; init; }
    public bool IsLimited => TotalCount > Groups.Count;
}

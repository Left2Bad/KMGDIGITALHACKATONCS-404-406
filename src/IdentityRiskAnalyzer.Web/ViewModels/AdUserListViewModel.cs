namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class AdUserListViewModel
{
    public IReadOnlyList<AdUserListItemViewModel> Users { get; init; } = Array.Empty<AdUserListItemViewModel>();
    public int TotalCount { get; init; }
    public int DisplayLimit { get; init; }
    public string? ErrorMessage { get; init; }
    public bool IsLimited => TotalCount > Users.Count;
}

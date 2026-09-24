namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class AdUserListItemViewModel
{
    public Guid ObjectGuid { get; init; }
    public string? SamAccountName { get; init; }
    public string? DisplayName { get; init; }
    public string? UserPrincipalName { get; init; }
    public DateTimeOffset? LastKnownActivityUtc { get; init; }
    public DateTimeOffset? PasswordLastSetUtc { get; init; }
    public int SpnCount { get; init; }
    public string DistinguishedName { get; init; } = string.Empty;
    public bool IsPrivileged { get; init; }
    public int PrivilegedGroupCount { get; init; }
    public ServiceAccountClassificationViewModel ServiceAccountClassification { get; init; } = new();
}

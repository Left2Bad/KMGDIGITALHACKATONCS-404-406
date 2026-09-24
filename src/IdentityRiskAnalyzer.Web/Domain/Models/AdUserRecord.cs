namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class AdUserRecord
{
    public required Guid ObjectGuid { get; init; }
    public string? Sid { get; init; }
    public required string DistinguishedName { get; init; }
    public string? SamAccountName { get; init; }
    public string? UserPrincipalName { get; init; }
    public string? DisplayName { get; init; }
    public long UserAccountControl { get; init; }
    public long? ComputedUserAccountControl { get; init; }
    public DateTimeOffset? LastKnownActivityUtc { get; init; }
    public DateTimeOffset? PasswordLastSetUtc { get; init; }
    public DateTimeOffset? AccountExpiresUtc { get; init; }
    public long? LockoutTimeRaw { get; init; }
    public int? PrimaryGroupId { get; init; }
    public IReadOnlyList<string> MemberOfDistinguishedNames { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> ServicePrincipalNames { get; init; } = Array.Empty<string>();
    public string? ManagedBy { get; init; }
    public string? Description { get; init; }
    public IReadOnlyList<string> SidHistory { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> AllowedToDelegateTo { get; init; } = Array.Empty<string>();
    public bool HasResourceBasedConstrainedDelegation { get; init; }
    public IReadOnlyList<string> ObjectClasses { get; init; } = Array.Empty<string>();
}

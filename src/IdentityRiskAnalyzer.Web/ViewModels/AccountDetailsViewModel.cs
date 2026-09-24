using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class AccountDetailsViewModel
{
    public long ScanRunId { get; init; }
    public DateTimeOffset ScanTimestampUtc { get; init; }
    public ScanStatus ScanStatus { get; init; }
    public Guid ObjectGuid { get; init; }
    public AdObjectType ObjectType { get; init; }
    public string? SamAccountName { get; init; }
    public string? DisplayName { get; init; }
    public string? UserPrincipalName { get; init; }
    public string DistinguishedName { get; init; } = string.Empty;
    public string? Sid { get; init; }
    public bool? Enabled { get; init; }
    public bool? Locked { get; init; }
    public bool? AccountExpired { get; init; }
    public DateTimeOffset? LastKnownActivityUtc { get; init; }
    public DateTimeOffset? PasswordLastSetUtc { get; init; }
    public bool? PasswordNeverExpires { get; init; }
    public bool IsServiceAccount { get; init; }
    public bool IsPrivileged { get; init; }
    public int RiskScore { get; init; }
    public RiskSeverity RiskLevel { get; init; }
    public int FindingsCount => Findings.Count;
    public long AccumulatedPoints { get; init; }
    public bool WasCapped => AccumulatedPoints > 100;
    public IReadOnlyList<HistoricalMembershipViewModel> PrivilegeMemberships { get; init; } = [];
    public IReadOnlyList<HistoricalMembershipViewModel> GroupMemberships { get; init; } = [];
    public int GroupMembershipCount { get; init; }
    public int MembershipPage { get; init; } = 1;
    public int MembershipPageSize { get; init; } = 50;
    public int MembershipPageCount => Math.Max(1, (GroupMembershipCount + MembershipPageSize - 1) / MembershipPageSize);
    public IReadOnlyList<HistoricalDelegationViewModel> DelegationRecords { get; init; } = [];
    public IReadOnlyList<HistoricalFindingViewModel> Findings { get; init; } = [];
    public string AccountName => DisplayName ?? SamAccountName ?? UserPrincipalName ?? DistinguishedName;
}

public sealed class HistoricalMembershipViewModel
{
    public Guid GroupObjectGuid { get; init; }
    public string GroupName { get; init; } = string.Empty;
    public string GroupDistinguishedName { get; init; } = string.Empty;
    public bool IsDirect { get; init; }
    public int Depth { get; init; }
    public bool IsPrivileged { get; init; }
    public IReadOnlyList<string> PathDisplayNames { get; init; } = [];
    public bool PathAvailable { get; init; }
}

public sealed class HistoricalDelegationViewModel
{
    public DelegationType DelegationType { get; init; }
    public IReadOnlyList<string> Targets { get; init; } = [];
    public bool TargetsAvailable { get; init; }
}

public sealed class HistoricalFindingViewModel
{
    public RiskSeverity Severity { get; init; }
    public string RuleId { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string? Evidence { get; init; }
    public string Recommendation { get; init; } = string.Empty;
    public int RiskPoints { get; init; }
    public int ScoreContribution => Math.Max(RiskPoints, 0);
}

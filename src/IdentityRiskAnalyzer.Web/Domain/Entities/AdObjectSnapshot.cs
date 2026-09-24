using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Domain.Entities;

public class AdObjectSnapshot
{
    private DateTimeOffset? _lastKnownActivityUtc;
    private DateTimeOffset? _passwordLastSetUtc;

    public long Id { get; set; }
    public long ScanRunId { get; set; }
    public Guid ObjectGuid { get; set; }
    public string? Sid { get; set; }
    public AdObjectType ObjectType { get; set; }
    public string? SamAccountName { get; set; }
    public string? DisplayName { get; set; }
    public string DistinguishedName { get; set; } = string.Empty;
    public string? UserPrincipalName { get; set; }
    public bool? Enabled { get; set; }
    public bool? Locked { get; set; }
    public bool? AccountExpired { get; set; }
    public bool IsServiceAccount { get; set; }
    public bool IsPrivileged { get; set; }
    public DateTimeOffset? LastKnownActivityUtc
    {
        get => _lastKnownActivityUtc;
        set => _lastKnownActivityUtc = value?.ToUniversalTime();
    }
    public DateTimeOffset? PasswordLastSetUtc
    {
        get => _passwordLastSetUtc;
        set => _passwordLastSetUtc = value?.ToUniversalTime();
    }
    public bool? PasswordNeverExpires { get; set; }
    public int RiskScore { get; set; }
    public RiskSeverity RiskLevel { get; set; }

    public ScanRun ScanRun { get; set; } = null!;
}

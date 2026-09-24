using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Domain.Entities;

public class ScanRun
{
    private DateTimeOffset _startedAtUtc;
    private DateTimeOffset? _finishedAtUtc;

    public long Id { get; set; }
    public DateTimeOffset StartedAtUtc
    {
        get => _startedAtUtc;
        set => _startedAtUtc = value.ToUniversalTime();
    }
    public DateTimeOffset? FinishedAtUtc
    {
        get => _finishedAtUtc;
        set => _finishedAtUtc = value?.ToUniversalTime();
    }
    public ScanStatus Status { get; set; } = ScanStatus.Pending;
    public string Server { get; set; } = string.Empty;
    public string BaseDn { get; set; } = string.Empty;
    public int ObjectsScanned { get; set; }
    public int FindingsCount { get; set; }
    public int ErrorsCount { get; set; }
    public int? AdSecurityScore { get; set; }
    public string? ErrorMessage { get; set; }

    public ICollection<AdObjectSnapshot> AdObjectSnapshots { get; set; } = new List<AdObjectSnapshot>();
    public ICollection<GroupMembership> GroupMemberships { get; set; } = new List<GroupMembership>();
    public ICollection<DelegationRecord> DelegationRecords { get; set; } = new List<DelegationRecord>();
    public ICollection<RiskFinding> RiskFindings { get; set; } = new List<RiskFinding>();
}

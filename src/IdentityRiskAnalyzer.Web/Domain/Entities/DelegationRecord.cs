using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Domain.Entities;

public class DelegationRecord
{
    public long Id { get; set; }
    public long ScanRunId { get; set; }
    public Guid ObjectGuid { get; set; }
    public string ObjectName { get; set; } = string.Empty;
    public DelegationType DelegationType { get; set; }
    public string? TargetsJson { get; set; }

    public ScanRun ScanRun { get; set; } = null!;
}

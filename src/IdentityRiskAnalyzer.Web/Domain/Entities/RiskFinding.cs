using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Domain.Entities;

public class RiskFinding
{
    public long Id { get; set; }
    public long ScanRunId { get; set; }
    public Guid ObjectGuid { get; set; }
    public AdObjectType ObjectType { get; set; }
    public string ObjectName { get; set; } = string.Empty;
    public string RuleId { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? Evidence { get; set; }
    public string Recommendation { get; set; } = string.Empty;
    public int RiskPoints { get; set; }
    public RiskSeverity Severity { get; set; }

    public ScanRun ScanRun { get; set; } = null!;
}

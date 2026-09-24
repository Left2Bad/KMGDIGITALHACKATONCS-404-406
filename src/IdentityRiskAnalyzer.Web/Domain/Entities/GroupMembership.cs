namespace IdentityRiskAnalyzer.Web.Domain.Entities;

public class GroupMembership
{
    public long Id { get; set; }
    public long ScanRunId { get; set; }
    public Guid PrincipalObjectGuid { get; set; }
    public Guid GroupObjectGuid { get; set; }
    public string GroupName { get; set; } = string.Empty;
    public string GroupDistinguishedName { get; set; } = string.Empty;
    public bool IsDirect { get; set; }
    public int Depth { get; set; }
    public string PathJson { get; set; } = "[]";
    public bool IsPrivileged { get; set; }

    public ScanRun ScanRun { get; set; } = null!;
}

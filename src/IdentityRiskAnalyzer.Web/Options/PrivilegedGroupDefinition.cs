namespace IdentityRiskAnalyzer.Web.Options;

public sealed class PrivilegedGroupDefinition
{
    public string Name { get; set; } = string.Empty;
    public string? Sid { get; set; }
    public int? Rid { get; set; }
    public bool Enabled { get; set; } = true;
    public string? Category { get; set; }
}

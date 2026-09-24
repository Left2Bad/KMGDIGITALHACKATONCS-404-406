namespace IdentityRiskAnalyzer.Web.Options;

public sealed class PrivilegeAnalysisOptions
{
    public const string SectionName = "PrivilegeAnalysis";

    public List<PrivilegedGroupDefinition> PrivilegedGroups { get; set; } = [];
}

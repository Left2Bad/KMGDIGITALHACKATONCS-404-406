using System.ComponentModel.DataAnnotations;

namespace IdentityRiskAnalyzer.Web.Options;

public sealed class GroupAnalysisOptions
{
    public const string SectionName = "GroupAnalysis";

    [Range(1, 256)]
    public int MaxGroupNestingDepth { get; set; } = 64;
}

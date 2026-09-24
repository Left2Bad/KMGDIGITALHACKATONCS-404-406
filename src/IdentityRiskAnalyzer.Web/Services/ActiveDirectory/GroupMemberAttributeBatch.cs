namespace IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

public sealed record GroupMemberAttributeBatch(
    IReadOnlyList<string> Members,
    bool HasMemberAttribute,
    bool HasRangedAttribute,
    bool IsComplete,
    bool IsMalformed,
    long? FirstRangeStart,
    long? NextRangeStart);

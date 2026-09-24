using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class ScanExecutionResult
{
    public long ScanRunId { get; init; }
    public ScanStatus Status { get; init; }
    public bool AlreadyRunning { get; init; }
    public int ObjectsScanned { get; init; }
    public int FindingsCount { get; init; }
    public int ErrorsCount { get; init; }
    public int? AdSecurityScore { get; init; }
    public TimeSpan Duration { get; init; }
    public string? ErrorMessage { get; init; }
}

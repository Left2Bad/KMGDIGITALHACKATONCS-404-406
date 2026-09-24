using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class ScanListViewModel
{
    public IReadOnlyList<ScanListItemViewModel> Scans { get; init; } = [];
    public string? Message { get; init; }
}

public sealed class ScanListItemViewModel
{
    public long Id { get; init; }
    public DateTimeOffset StartedAtUtc { get; init; }
    public DateTimeOffset? FinishedAtUtc { get; init; }
    public ScanStatus Status { get; init; }
    public string Server { get; init; } = string.Empty;
    public int ObjectsScanned { get; init; }
    public int FindingsCount { get; init; }
    public int ErrorsCount { get; init; }
    public int? AdSecurityScore { get; init; }
    public TimeSpan? Duration => FinishedAtUtc - StartedAtUtc;
}

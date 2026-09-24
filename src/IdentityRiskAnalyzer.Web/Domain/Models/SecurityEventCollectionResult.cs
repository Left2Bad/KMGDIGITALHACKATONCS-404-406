using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class SecurityEventCollectionResult
{
    public SecurityEventCollectionStatus Status { get; init; }
    public IReadOnlyList<SecurityAuthenticationEvent> Events { get; init; } = [];
    public int EventsRead { get; init; }
    public int EventsSkipped { get; init; }
    public bool WasTruncated { get; init; }
    public string? ErrorMessage { get; init; }
}

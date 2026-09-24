using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class AuthenticationThreat
{
    public required AuthenticationThreatType Type { get; init; }
    public string? Source { get; init; }
    public required DateTimeOffset WindowStartUtc { get; init; }
    public required DateTimeOffset WindowEndUtc { get; init; }
    public required int FailedAttempts { get; init; }
    public required IReadOnlyList<string> AffectedUserNames { get; init; }
}

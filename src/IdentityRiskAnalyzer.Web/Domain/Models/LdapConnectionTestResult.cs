using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class LdapConnectionTestResult
{
    public bool Success { get; init; }
    public string Server { get; init; } = string.Empty;
    public int Port { get; init; }
    public bool UseSsl { get; init; }
    public string Message { get; init; } = string.Empty;
    public long DurationMs { get; init; }
    public LdapConnectionErrorType ErrorType { get; init; }
}

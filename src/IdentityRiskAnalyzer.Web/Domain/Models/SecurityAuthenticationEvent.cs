namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class SecurityAuthenticationEvent
{
    public DateTimeOffset TimestampUtc { get; init; }
    public int EventId { get; init; }
    public long? RecordId { get; init; }
    public string? TargetUserName { get; init; }
    public string? TargetDomainName { get; init; }
    public string? SourceIpAddress { get; init; }
    public string? WorkstationName { get; init; }
    public string? LogonType { get; init; }
    public string? FailureReason { get; init; }
    public string? Status { get; init; }
    public string? SubStatus { get; init; }
    public bool IsFailedAuthentication => EventId is 4625 or 4771 or 4776;
}

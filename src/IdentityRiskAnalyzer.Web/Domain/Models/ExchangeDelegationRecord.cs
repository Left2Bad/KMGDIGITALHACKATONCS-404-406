using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Domain.Models;

public sealed class ExchangeDelegationRecord
{
    public required string MailboxIdentity { get; init; }
    public Guid? MailboxGuid { get; init; }
    public required string Trustee { get; init; }
    public required ExchangeDelegationType DelegationType { get; init; }
    public bool Inherited { get; init; }
    public required string Source { get; init; }
}

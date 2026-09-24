using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.Exchange;

public interface IExchangeDelegationCollector
{
    ExchangeDelegationCollectionResult Collect(CancellationToken cancellationToken);
}

public sealed class ExchangeDelegationCollectionResult
{
    public bool Enabled { get; init; }
    public bool Available { get; init; }
    public IReadOnlyList<ExchangeDelegationRecord> Records { get; init; } = [];
    public string? Message { get; init; }
}

using IdentityRiskAnalyzer.Web.Options;
using Microsoft.Extensions.Options;

namespace IdentityRiskAnalyzer.Web.Services.Exchange;

// The optional Exchange inventory contract is reserved until a supported Exchange
// session can be verified. It never reports fabricated mailbox permissions.
public sealed class UnavailableExchangeDelegationCollector(IOptions<ExchangeDelegationOptions> options) : IExchangeDelegationCollector
{
    public ExchangeDelegationCollectionResult Collect(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return options.Value.Enabled
            ? new() { Enabled = true, Available = false, Message = "Exchange delegation collection is not configured in this deployment." }
            : new() { Enabled = false, Available = false };
    }
}
